#!/usr/bin/env python3
"""
Validate that Lambda functions have functionally identical IAM permissions
between old and new accounts, regardless of policy organization.
"""

import boto3
import sys
from typing import Dict, Set


def get_lambda_client(profile: str, region: str):
    """Get Lambda client for specified profile and region."""
    try:
        session = boto3.Session(profile_name=profile)
        client = session.client("lambda", region_name=region)
        client.list_functions(MaxItems=1)
        return client
    except Exception as e:
        if "Token has expired" in str(e) or "sso" in str(e).lower():
            print(f"SSO token expired for profile {profile}.")
            print(f"Please run: aws sso login --profile {profile}")
            sys.exit(1)
        else:
            raise e


def get_iam_client(profile: str, region: str):
    """Get IAM client for specified profile and region."""
    try:
        session = boto3.Session(profile_name=profile)
        client = session.client("iam", region_name=region)
        client.list_roles(MaxItems=1)
        return client
    except Exception as e:
        if "Token has expired" in str(e) or "sso" in str(e).lower():
            print(f"SSO token expired for profile {profile}.")
            print(f"Please run: aws sso login --profile {profile}")
            sys.exit(1)
        else:
            raise e


def normalize_permission(action: str, resource: str) -> str:
    """Normalize a permission to a comparable format."""
    # Replace account IDs and environment-specific parts with placeholders
    normalized_resource = resource
    normalized_resource = normalized_resource.replace("653994557586", "ACCOUNT_ID")
    normalized_resource = normalized_resource.replace("975050272416", "ACCOUNT_ID")
    normalized_resource = normalized_resource.replace("authdev1", "ENV")
    normalized_resource = normalized_resource.replace("authdev2", "ENV")
    normalized_resource = normalized_resource.replace("authdev3", "ENV")
    normalized_resource = normalized_resource.replace("dev", "ENV")

    return f"{action}:{normalized_resource}"


def extract_permissions_from_policy(policy_doc: Dict) -> Set[str]:
    """Extract normalized permissions from a policy document."""
    permissions = set()

    if "Statement" not in policy_doc:
        return permissions

    statements = policy_doc["Statement"]
    if not isinstance(statements, list):
        statements = [statements]

    for statement in statements:
        if statement.get("Effect") != "Allow":
            continue

        actions = statement.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]

        resources = statement.get("Resource", ["*"])
        if isinstance(resources, str):
            resources = [resources]

        for action in actions:
            for resource in resources:
                permissions.add(normalize_permission(action, resource))

    return permissions


def get_function_permissions(lambda_client, iam_client, function_name: str) -> Set[str]:
    """Get all effective permissions for a Lambda function."""
    try:
        # Get function configuration
        func_config = lambda_client.get_function(FunctionName=function_name)
        role_arn = func_config["Configuration"]["Role"]
        role_name = role_arn.split("/")[-1]

        # Get role policies
        all_permissions = set()

        # Get attached managed policies
        paginator = iam_client.get_paginator("list_attached_role_policies")
        for page in paginator.paginate(RoleName=role_name):
            for policy in page["AttachedPolicies"]:
                policy_arn = policy["PolicyArn"]

                # Get policy version
                policy_info = iam_client.get_policy(PolicyArn=policy_arn)
                default_version = policy_info["Policy"]["DefaultVersionId"]

                # Get policy document
                policy_version = iam_client.get_policy_version(
                    PolicyArn=policy_arn, VersionId=default_version
                )

                policy_doc = policy_version["PolicyVersion"]["Document"]
                permissions = extract_permissions_from_policy(policy_doc)
                all_permissions.update(permissions)

        # Get inline policies
        paginator = iam_client.get_paginator("list_role_policies")
        for page in paginator.paginate(RoleName=role_name):
            for policy_name in page["PolicyNames"]:
                policy_doc = iam_client.get_role_policy(
                    RoleName=role_name, PolicyName=policy_name
                )["PolicyDocument"]

                permissions = extract_permissions_from_policy(policy_doc)
                all_permissions.update(permissions)

        return all_permissions

    except Exception as e:
        print(f"Error getting permissions for {function_name}: {e}")
        return set()


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Validate Lambda function permissions are identical"
    )
    parser.add_argument(
        "--old-profile", required=True, help="AWS profile for old account"
    )
    parser.add_argument(
        "--new-profile", required=True, help="AWS profile for new account"
    )
    parser.add_argument(
        "--old-function", required=True, help="Function name in old account"
    )
    parser.add_argument(
        "--new-function", required=True, help="Function name in new account"
    )
    parser.add_argument("--region", default="eu-west-2", help="AWS region")

    args = parser.parse_args()

    # Get clients
    old_lambda = get_lambda_client(args.old_profile, args.region)
    old_iam = get_iam_client(args.old_profile, args.region)
    new_lambda = get_lambda_client(args.new_profile, args.region)
    new_iam = get_iam_client(args.new_profile, args.region)

    print("Comparing permissions:")
    print(f"  Old: {args.old_function}")
    print(f"  New: {args.new_function}")
    print()

    # Get permissions
    old_permissions = get_function_permissions(old_lambda, old_iam, args.old_function)
    new_permissions = get_function_permissions(new_lambda, new_iam, args.new_function)

    # Compare permissions
    missing_in_new = old_permissions - new_permissions
    extra_in_new = new_permissions - old_permissions
    common_permissions = old_permissions & new_permissions

    print("📊 Permission Analysis:")
    print(f"  Common permissions: {len(common_permissions)}")
    print(f"  Missing in new: {len(missing_in_new)}")
    print(f"  Extra in new: {len(extra_in_new)}")
    print()

    if missing_in_new:
        print("🔴 Missing permissions in new account:")
        for perm in sorted(missing_in_new):
            print(f"  - {perm}")
        print()

    if extra_in_new:
        print("🟡 Extra permissions in new account:")
        for perm in sorted(extra_in_new):
            print(f"  - {perm}")
        print()

    if not missing_in_new and not extra_in_new:
        print("✅ Permissions are functionally identical!")
        return 0
    elif not missing_in_new:
        print("⚠️  New account has additional permissions but no missing ones")
        return 0
    else:
        print("❌ New account is missing critical permissions")
        return 1


if __name__ == "__main__":
    sys.exit(main())
