package uk.gov.di.orchestration.local;

import software.amazon.awssdk.services.kms.model.KeyUsageType;
import uk.gov.di.orchestration.local.initialisers.DynamoDbInitialiser;
import uk.gov.di.orchestration.local.initialisers.KmsInitialiser;
import uk.gov.di.orchestration.local.initialisers.ParameterInitialiser;
import uk.gov.di.orchestration.local.initialisers.SqsInitialiser;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.entity.ClientType;
import uk.gov.di.orchestration.shared.entity.ServiceType;

import java.util.List;

import static java.lang.String.valueOf;

public class App {
    public static void main(String[] args) {
        initialiseDownstreamComponents();
        new LocalOrchestrationApi();
    }

    // Initialise downstream components in Localstack and DynamoDB
    //
    // It might be nice to commonise this with the integration test setup,
    // (see BaseAwsResourceExtension, ParameterStoreExtension etc.)
    // or replace entirely with local stubs/config
    private static void initialiseDownstreamComponents() {
        // Set up localstack SSM parameters
        //
        // Once Redis is gone we could remove SSM entirely and use environment variables
        var parameterInitialiser = new ParameterInitialiser();
        parameterInitialiser.setParam("local-session-redis-master-host", "host.docker.internal");
        parameterInitialiser.setParam("local-session-redis-port", valueOf(6379));
        parameterInitialiser.setParam("local-session-redis-tls", valueOf(false));
        // Remove this once using JWKS for auth
        parameterInitialiser.setParam("local-auth-public-encryption-key", System.getenv("ORCH_TO_AUTH_ENCRYPTION_PUBLIC_KEY"));

        // Set up localstack KMS keys
        //
        // In future these signing operations could use a local key instead
        var kmsInitialiser = new KmsInitialiser();
        kmsInitialiser.createKey("alias/local-auth-token-signing-key", KeyUsageType.SIGN_VERIFY);
        kmsInitialiser.createKey("alias/local-doc-app-token-signing-key", KeyUsageType.SIGN_VERIFY);
        kmsInitialiser.createKey("alias/local-external-token-signing-key", KeyUsageType.SIGN_VERIFY);
        kmsInitialiser.createKey("alias/local-ipv-token-signing-key", KeyUsageType.SIGN_VERIFY);
        kmsInitialiser.createKey("alias/local-storage-token-signing-key", KeyUsageType.SIGN_VERIFY);

        // Set up localstack SQS queues
        //
        // Without consumers for these queues these are effectively just DLQs
        // and could be replaced with a stub implementation
        var sqsInitialiser = new SqsInitialiser();
        sqsInitialiser.createQueue("local-backchannel-logout-queue");
        sqsInitialiser.createQueue("local-spot-queue");
        sqsInitialiser.createQueue("local-txma-audit-queue");

        // Set up data in the DynamoDB tables
        //
        // Most tables are initialised automatically in the 'warm up' step
        var dynamoInitialiser = new DynamoDbInitialiser();
        dynamoInitialiser.addRecords(
                "local-client-registry",
                ClientRegistry.class,
                List.of(
                        new ClientRegistry()
                                .withClientID("local-client-id")
                                .withClientName("local-client-name")
                                .withRedirectUrls(List.of("http://local-rp/redirect"))
                                .withScopes(List.of("openid", "email"))
                                .withPublicKey("placeholder-key")
                                .withServiceType(ServiceType.MANDATORY.name())
                                .withSubjectType("public")
                                .withClientType(ClientType.WEB.name())
                                .withIdentityVerificationSupported(true)
                                .withTestClient(true)
                                .withTestClientEmailAllowlist(List.of("^.*$"))));
    }
}
