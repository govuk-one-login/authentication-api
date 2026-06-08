import json
import logging
import os

import boto3
import botocore

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def lambda_handler(event, context):
    """Origin Cloaking Header Managed Secret Rotation Lambda

    This lambda is responsible for rotating the managed secret for the devplatform cloudformation-distribution stack.
    The secret value is used to ensure that only traffic originating from the cloudfront distribution can access its origin resource. See the cloudfront-distribution template for more details.

    To allow an update of the secret value the template uses the AWSPREVIOUS in the WAF rules so there will be no traffic blocked. This requires the secret rotation to run as soon as the secret is generated. This is handled by skipping the setSecret and testSecret functions if no AWSPREVIOUS secret stage exists, and the stack is in an CREATE_IN_PROGRESS or UPDATE_IN_PROGRESS state. During this initial rotation the lambda must also signal to the stack's WaitCondition resource to indicate the secret holds two versions.

    Args:
        event (dict): Lambda dictionary of event parameters. These keys must include the following:
            - SecretId: The secret ARN or identifier
            - ClientRequestToken: The ClientRequestToken of the secret version
            - Step: The rotation step (one of createSecret, setSecret, testSecret, or finishSecret)

        context (LambdaContext): The Lambda runtime information

    Raises:
        ResourceNotFoundException: If the secret with the specified arn and stage does not exist

        ValueError: If the secret is not properly configured for rotation

        KeyError: If the event parameters do not contain the expected keys
    """
    arn = event["SecretId"]
    token = event["ClientRequestToken"]  # Used as the incoming och vid.
    step = event["Step"]

    logger.info(
        "lambdaHandler: Secret Rotation Step: %s. ClientRequestToken / OPH Incoming Version Id:  %s."
        % (step, token)
    )

    arn = event["SecretId"]
    och_arn = os.environ["ORIGIN_CLOAKING_HEADER_MANAGED_SECRET"]

    # Verify the lambda is being used for the intended secret
    if arn != och_arn:
        logger.error(
            "lambdaHandler: Secret Rotation Lambda env var ORIGIN_CLOAKING_HEADER_MANAGED_SECRET incorrectly configured"
        )
        raise ValueError(
            "lambdaHandler: Secret Rotation Lambda env var ORIGIN_CLOAKING_HEADER_MANAGED_SECRET incorrectly configured"
        )

    secretsmanager = boto3.client("secretsmanager")

    # Retrieve current state of the secrets
    och_description = secretsmanager.describe_secret(SecretId=och_arn)
    och_vids = get_secret_vids(och_description)
    och_vids["incoming"] = event["ClientRequestToken"]

    logger.debug(
        "lambdaHandler:  OPH version ids to stages: %s."
        % (och_description["VersionIdsToStages"])
    )

    logger.info(
        "lambdaHandler:  OPH version ids: INCOMING %s; PENDING %s; CURRENT %s; PREVIOUS %s."
        % (
            och_vids["incoming"],
            och_vids["pending"],
            och_vids["current"],
            och_vids["previous"],
        )
    )

    # Make sure the new value is staged correctly on every run of the lambda. This helps ensure nothing has changed during rotation.

    # Perform checks against current state to ensure rotation is continuing successfully.
    if not och_description["RotationEnabled"]:
        logger.error("lambdaHandler: Secret %s is not enabled for rotation" % och_arn)
        raise ValueError(
            "lambdaHandler: Secret %s is not enabled for rotation" % och_arn
        )

    # Return early if secrets are in the end state.
    if och_vids["incoming"] == och_vids["current"]:
        logger.info(
            "lambdaHandler: The incoming version id is already set as AWSCURRENT. Returning early"
        )
        return

    # Raise error if the AWSPENDING stage is associated with an unexpected version-id. This suggest secrets are in an incomplete rotation state.
    # Checks that current != pending as that is a valid state during createSecret
    # Manual intervention will be required to fix.
    if (
        och_vids["pending"]
        and och_vids["current"] != och_vids["pending"]
        and och_vids["incoming"] != och_vids["pending"]
    ):
        logger.error(
            "lambdaHandler: Incoming secret version id not set as AWSPENDING for rotation of secret. Manual intervention likely, please verify current state of secrets and stack resources before continuing."
        )
        raise ValueError(
            "lambdaHandler: Incoming secret version id not set as AWSPENDING for rotation of secret. Manual intervention likely, please verify current state of secrets and stack resources before continuing."
        )

    cloudformation = boto3.client("cloudformation")

    stack_create_in_progress = False
    stack_arn = os.environ["STACK_ID"]
    stack_description = cloudformation.describe_stacks(StackName=stack_arn)["Stacks"][0]

    if stack_description["StackStatus"] in ["CREATE_IN_PROGRESS"]:
        logger.info(
            "lambdaHandler: This lambda is called during stack creation so is the initial rotation. Continuing with the rotation without updating the stack to ensure an AWSPREVIOUS secret version is present."
        )
        stack_create_in_progress = True

    # The secret can be created optionally so it is possible to create a new secret during an update.
    if (
        stack_description["StackStatus"] == "UPDATE_IN_PROGRESS"
        and not och_vids["previous"]
    ):
        logger.info(
            "lambdaHandler: This lambda is called during stack update but has no AWSPREVIOUS value. Continuing with the rotation without updating the stack to ensure an AWSPREVIOUS secret version is present."
        )
        stack_create_in_progress = True

    # Run step specific code
    if step == "createSecret":
        create_secret(secretsmanager, och_arn, och_vids)

    elif step == "setSecret":
        if stack_create_in_progress:
            logger.info(
                "setSecret: Lambda running during stack creation, skipping setSecret and the intended stack update."
            )
            return
        else:
            set_secret(och_vids)

    elif step == "testSecret":
        if stack_create_in_progress:
            logger.info(
                "testSecret: Lambda running during stack creation, skipping testSecret and the intended check that the stack update has completed."
            )
            return
        else:
            test_secret(och_vids)

    elif step == "finishSecret":
        finish_secret(secretsmanager, och_description)

        if stack_create_in_progress:
            logger.info(
                "finishSecret: Calling cloudformation signal resource on initial run"
            )
            cloudformation.signal_resource(
                StackName=stack_arn,
                LogicalResourceId=os.environ["WAIT_CONDITION_LOGICAL_ID"],
                UniqueId="finishSecret",
                Status="SUCCESS",
            )

        try:
            notification_sns_arn = os.environ["NOTIFICATION_SNS_ARN"]
            try:
                send_notification(notification_sns_arn, stack_arn, och_arn, och_vids)
            except Exception as err:
                logger.error(
                    "finishSecret: SNS success notification FAILED."
                )  # Used in a metric log filter. If changing this string change the metric log filter.
                logger.info(
                    "finishSecret: SNS success notification FAILED. Check Env Var, Lambda permissions or request body. Err: %s"
                    % err
                )
        except Exception as e:
            logger.info("finishSecret: SNS success notification not configured. %s" % e)

    else:
        raise ValueError("Invalid step parameter")


def create_secret(secretsmanager, och_arn, och_vids):
    """Create the secrets

    This method will create a the pending secret version for the OCH using the OCH incoming version-id / ClientRequestToken

    To ensure this method can be re-run using the same OCH incoming version-id / ClientRequestToken it first checks if a secret version
    using that id exists and returns early if so.

    Args:
        secretsmanager (client): The secrets manager service client
        arn (string): The secret ARN or other identifier
        token (string): The ClientRequestToken associated with the secret version

    Raises:
        ResourceNotFoundException: If the secret with the specified arn and stage does not exist
        ValueError: If the incoming secret exists but is not marked as AWSPENDING
    """

    # Make sure the current secret exists # This is from the template. I assume it is done to error out if the version stage had been removed.
    secretsmanager.get_secret_value(SecretId=och_arn, VersionStage="AWSCURRENT")

    # Generate a new value for the Origin Cloaking Header Secret
    try:
        och_incoming_secret = secretsmanager.get_secret_value(
            SecretId=och_arn,
            VersionId=och_vids["incoming"],
        )
        logger.info(
            "createSecret: Successfully retrieved pending secret for %s. VersionId: %s. VersionStages: %s."
            % (
                och_incoming_secret["ARN"],
                och_incoming_secret["VersionId"],
                och_incoming_secret["VersionStages"],
            )
        )

        if "AWSPENDING" not in och_incoming_secret["VersionStages"]:
            logger.error(
                "createSecret: Managed to retrieve secret %s for version id %s but it is not marked as AWSPENDING. This is an incorrect state."
                % (och_arn, och_vids["incoming"])
            )
            raise ValueError(
                "createSecret: Managed to retrieve secret %s for version id %s but it is not marked as AWSPENDING. This is an incorrect state."
                % (och_arn, och_vids["incoming"])
            )

    except secretsmanager.exceptions.ResourceNotFoundException:
        passwd = secretsmanager.get_random_password(ExcludePunctuation=True)

        secretsmanager.put_secret_value(
            SecretId=och_arn,
            ClientRequestToken=och_vids["incoming"],
            SecretString=passwd["RandomPassword"],
            VersionStages=["AWSPENDING"],
        )
        logger.info(
            "createSecret: Successfully put secret for ARN: %s. Incoming version id: %s."
            % (och_arn, och_vids["incoming"])
        )


def set_secret(och_vids):
    """Set the secret

    Updates the stack to use the OPH-Pending VersionID and the OPH-Current VersionIDs.
    The CloudFormation client returns an error if there are no updates to perform. In this case we capture the error and return a success code to ensure idempotency.

    Args:
        och_vids (dict): A dict holding each version stage and its associated versionId. The incoming and pending values should be equivalent and match the ClientRequestToken.

    Raises:
        RuntimeError: If update_stack fails

        ValueError: If the pending and incoming version ids do not corroborate.
    """

    if och_vids["pending"] != och_vids["incoming"]:
        logger.error(
            "setSecret: The pending and incoming version ids do not agree for this step. Please verify secret state"
        )
        raise ValueError(
            "setSecret: The pending and incoming version ids do not agree for this step. Please verify secret state"
        )

    cloudformation = boto3.client("cloudformation")

    stack_arn = os.environ["STACK_ID"]
    stack_description = cloudformation.describe_stacks(StackName=stack_arn)["Stacks"][0]
    stack_parameters = stack_description["Parameters"]
    stack_status = stack_description["StackStatus"]

    logger.info(
        "setSecret: stack description for %s: %s" % (stack_arn, stack_description)
    )

    if stack_status not in [
        "CREATE_COMPLETE",
        "UPDATE_COMPLETE",
        "UPDATE_ROLLBACK_COMPLETE",
    ]:
        logger.error(
            "setSecret: Stack %s not in a valid status for updating. Stack status: %s"
            % (stack_arn, stack_status)
        )

    OriginCloakingHeaderManagedSecretVersion = och_vids["pending"]
    OriginCloakingHeaderManagedSecretPreviousVersion = och_vids["current"]

    if och_vids["pending"] == och_vids["current"]:
        # This state is possible if the client request token is used again
        logger.info(
            "setSecret: The incoming version id is already the current secret version. Using the previous version id for the stack deployment to preserve history."
        )
        OriginCloakingHeaderManagedSecretPreviousVersion = och_vids["previous"]

    logger.info(
        "setSecret: Setting OriginCloakingHeaderManagedSecretVersion         as %s"
        % (OriginCloakingHeaderManagedSecretVersion)
    )
    logger.info(
        "setSecret: Setting OriginCloakingHeaderManagedSecretPreviousVersion as %s"
        % (OriginCloakingHeaderManagedSecretPreviousVersion)
    )

    for p in stack_parameters:
        if p["ParameterKey"] == "OriginCloakingHeaderManagedSecretVersion":
            p["ParameterValue"] = ":" + OriginCloakingHeaderManagedSecretVersion
        elif p["ParameterKey"] == "OriginCloakingHeaderManagedSecretPreviousVersion":
            p["ParameterValue"] = ":" + OriginCloakingHeaderManagedSecretPreviousVersion
        else:
            del p["ParameterValue"]
            p["UsePreviousValue"] = True

    logger.info(
        "setSecret: Updating template with the following stack parameters: %s"
        % stack_parameters
    )

    try:
        cloudformation.update_stack(
            StackName=stack_arn,
            UsePreviousTemplate=True,
            Parameters=stack_parameters,
            Capabilities=[
                "CAPABILITY_IAM",
                "CAPABILITY_NAMED_IAM",
                "CAPABILITY_AUTO_EXPAND",
            ],
        )
        logger.info("setSecret: Stack update started for %s." % stack_arn)

    except botocore.exceptions.ClientError as error:
        e_str = str(error)
        if (
            "The submitted information didn't contain changes." in e_str
            or "No updates are to be performed" in e_str
        ):
            logger.info(
                "setSecret: Cloudformation update_stack has no updates to perform on %s."
                % stack_arn
            )
            return
        else:
            logger.error(
                "setSecret: Unable to update stack %s: %s " % (stack_arn, error)
            )
            raise RuntimeError(
                "setSecret: Unable to update stack %s: %s " % (stack_arn, error)
            )
    return


def test_secret(och_vids):
    """Test the secret

    This method should validate that the AWSPENDING secret works in the service that the secret belongs to.
    This is done by waiting for the cloudformation-distribution stack to succeed at updating
    CloudFront distributions take a few minutes to update so this lambda may fail initially depending on the lambda time out.

    Raises:
        RuntimeError: If the stack update fails to complete successfully

    """

    cf_client = boto3.client("cloudformation")

    stack_arn = os.environ["STACK_ID"]

    logger.info("testSecret: Waiting for stack %s to complete the update." % stack_arn)

    stack_update_waiter = cf_client.get_waiter("stack_update_complete")
    stack_update_waiter.wait(
        StackName=stack_arn,
        WaiterConfig={
            "Delay": 20,
            "MaxAttempts": 12,
        },  # Lambda timeout: 5 mins. Lambda Will wait Delay*MaxAttempts in seconds = 4m
    )

    stack_description = cf_client.describe_stacks(StackName=stack_arn)["Stacks"][0]
    stack_status = stack_description["StackStatus"]
    stack_status_reason = stack_description.get(
        "StackStatusReason", "No StackStatusReason given."
    )
    stack_parameters = stack_description["Parameters"]

    for p in stack_parameters:
        if p["ParameterKey"] == "OriginCloakingHeaderManagedSecretVersion":
            if p["ParameterValue"] != ":" + och_vids["pending"]:
                logger.error(
                    "testSecret: Stack update complete with incorrect parameter value for OriginCloakingHeaderManagedSecretVersion. Current Value: %s. Expected Value: %s."
                    % (p["ParameterValue"], ":" + och_vids["pending"])
                )
                raise ValueError(
                    "testSecret: Stack update complete with incorrect parameter value for OriginCloakingHeaderManagedSecretVersion. Current Value: %s. Expected Value: %s."
                    % (p["ParameterValue"], ":" + och_vids["pending"])
                )
        elif p["ParameterKey"] == "OriginCloakingHeaderManagedSecretPreviousVersion":
            if p["ParameterValue"] != ":" + och_vids["current"]:
                logger.error(
                    "testSecret: Stack update complete with incorrect parameter value for OriginCloakingHeaderManagedSecretPreviousVersion. Current Value: %s. Expected Value: %s."
                    % (p["ParameterValue"], ":" + och_vids["current"])
                )
                raise ValueError(
                    "testSecret: Stack update complete with incorrect parameter value for OriginCloakingHeaderManagedSecretPreviousVersion. Current Value: %s. Expected Value: %s."
                    % (p["ParameterValue"], ":" + och_vids["current"])
                )

    logger.info("testSecret: Stack Description: %s" % stack_description)
    logger.info(
        "testSecret: Stack %s has finished updating with status of %s."
        % (stack_arn, stack_status)
    )

    if stack_status != "UPDATE_COMPLETE":
        logger.error(
            "lambdaHandler: Stack %s did not reach UPDATE_COMPLETE status." % stack_arn
        )
        raise RuntimeError(
            "lambdaHandler: Stack %s did not update successfully. Stack Status: %s. Stack Status Reason: %s"
            % (stack_arn, stack_status, stack_status_reason)
        )

    return


def finish_secret(secretsmanager, och_description):
    """Finish the secret

    This method finalizes the rotation process by marking the secret version passed in as the AWSCURRENT secret.

    Args:

    Raises:
        ResourceNotFoundException: If the secret with the specified arn does not exist

    """
    och_vids = get_secret_vids(och_description)

    logger.info("finishSecret: Found  OPH Current version id: %s", och_vids["current"])

    if och_vids["current"] != och_vids["pending"]:
        secretsmanager.update_secret_version_stage(
            SecretId=och_description["ARN"],
            VersionStage="AWSCURRENT",
            RemoveFromVersionId=och_vids["current"],
            MoveToVersionId=och_vids["pending"],
        )
        logger.info(
            "finishSecret:  Successfully set AWSCURRENT stage to version %s for secret %s."
            % (och_vids["pending"], och_description["ARN"])
        )

    logger.info("finishSecret: Successfully set AWSCURRENT stage for both secrets.")


# Utils
def get_vid_from_stage(versions, stage, throw_error=False):
    for versionId, stages in versions.items():
        if stage in stages:
            return versionId
    if throw_error:
        logger.error(get_vid_from_stage)
        raise RuntimeError(get_vid_from_stage)


def get_secret_vids(description):
    return {
        "pending": get_vid_from_stage(description["VersionIdsToStages"], "AWSPENDING"),
        "current": get_vid_from_stage(description["VersionIdsToStages"], "AWSCURRENT"),
        "previous": get_vid_from_stage(
            description["VersionIdsToStages"], "AWSPREVIOUS"
        ),
    }


def send_notification(notification_sns_arn, stack_arn, och_arn, och_vids):
    logger.info(
        "sendNotification: Found notification sns arn as %s" % notification_sns_arn
    )

    sns = boto3.client("sns")

    sns_message = {
        "version": 1.0,
        "source": "custom",
        "content": {
            "textType": "client-markdown",
            "title": "Origin Cloaking Header Managed Secret Rotation: Successful! :white_check_mark:",
            "description": "StackArn: `%s`\nSecretArn: `%s`\nNew Version Id: `%s`"
            % (stack_arn, och_arn, och_vids["incoming"]),
        },
    }

    sns_response = sns.publish(
        TopicArn=notification_sns_arn,
        Message=json.dumps(sns_message, indent=2, sort_keys=True, default=str),
        Subject="Origin Cloaking Header Managed Secret Rotation Successful",
    )

    if sns_response["MessageId"]:
        logger.info(
            "sendNotification: SNS message published successfully: %s"
            % sns_response["MessageId"]
        )
