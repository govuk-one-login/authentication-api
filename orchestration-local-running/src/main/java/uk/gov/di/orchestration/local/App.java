package uk.gov.di.orchestration.local;

import software.amazon.awssdk.services.kms.model.KeyUsageType;
import uk.gov.di.orchestration.local.initialisers.ClientConfigReader;
import uk.gov.di.orchestration.local.initialisers.DynamoDbInitialiser;
import uk.gov.di.orchestration.local.initialisers.KmsInitialiser;
import uk.gov.di.orchestration.local.initialisers.ParameterInitialiser;
import uk.gov.di.orchestration.local.initialisers.SqsInitialiser;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;

public class App {
    public static void main(String[] args) throws Exception {
        initialiseDownstreamComponents();
        new LocalOrchestrationApi();
    }

    // Initialise downstream components in Localstack and DynamoDB
    //
    // It might be nice to commonise this with the integration test setup,
    // (see BaseAwsResourceExtension, ParameterStoreExtension etc.)
    // or replace entirely with local stubs/config
    private static void initialiseDownstreamComponents() throws Exception {
        // Set up localstack SSM parameters
        // Remove this once using JWKS for auth
        var parameterInitialiser = new ParameterInitialiser();
        parameterInitialiser.setParam(
                "local-auth-public-encryption-key",
                System.getenv("ORCH_TO_AUTH_ENCRYPTION_PUBLIC_KEY"));
        parameterInitialiser.setParam("local-ipv-capacity", "1");

        // Set up localstack KMS keys
        //
        // In future these signing operations could use a local key instead
        var kmsInitialiser = new KmsInitialiser();
        kmsInitialiser.createKey("alias/local-auth-token-signing-key", KeyUsageType.SIGN_VERIFY);
        kmsInitialiser.createKey("alias/local-doc-app-token-signing-key", KeyUsageType.SIGN_VERIFY);
        kmsInitialiser.createKey(
                "alias/local-external-token-signing-key", KeyUsageType.SIGN_VERIFY);
        kmsInitialiser.createKey("alias/local-ipv-token-signing-key", KeyUsageType.SIGN_VERIFY);
        kmsInitialiser.createKey("alias/local-storage-token-signing-key", KeyUsageType.SIGN_VERIFY);

        // Set up localstack SQS queues
        //
        // Without consumers for these queues these are effectively just DLQs
        // and could be replaced with a stub implementation
        var sqsInitialiser = new SqsInitialiser();
        sqsInitialiser.createQueue("local-backchannel-logout-queue");
        sqsInitialiser.createQueue("local-spot-request-queue");
        sqsInitialiser.createQueue("local-spot-response-queue");
        sqsInitialiser.createQueue("local-txma-audit-queue");

        // Set up data in the DynamoDB tables
        //
        // Most tables are initialised automatically in the 'warm up' step
        var dynamoInitialiser = new DynamoDbInitialiser();
        dynamoInitialiser.addRecords(
                "local-client-registry",
                ClientRegistry.class,
                ClientConfigReader.getClientConfigs());
    }
}
