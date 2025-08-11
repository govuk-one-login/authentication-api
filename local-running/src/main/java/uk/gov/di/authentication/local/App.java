package uk.gov.di.authentication.local;

import software.amazon.awssdk.services.kms.model.KeyUsageType;
import uk.gov.di.authentication.local.initialisers.DynamoDbInitialiser;
import uk.gov.di.authentication.local.initialisers.KmsInitialiser;
import uk.gov.di.authentication.local.initialisers.ParameterInitialiser;
import uk.gov.di.authentication.local.initialisers.SqsInitialiser;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.ClientType;
import uk.gov.di.authentication.shared.entity.ServiceType;

import java.util.List;

import static java.lang.String.valueOf;

public class App {
    public static void main(String[] args) {
        initialiseDownstreamComponents();
        new LocalAuthApi();
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
        parameterInitialiser.setParam("local-password-pepper", "pepper");
        parameterInitialiser.setParam(
                "local-notify-callback-bearer-token", "notify-test-@bearer-token");

        // Set up localstack KMS keys
        //
        // These signing operations could use a local key instead
        // - The token signing key is purely internal
        // - MFA Reset needs a mock IPV Core to support those journeys
        var kmsInitialiser = new KmsInitialiser();
        kmsInitialiser.createKey("alias/local-token-signing-key", KeyUsageType.SIGN_VERIFY);
        kmsInitialiser.createKey(
                "alias/local-mfa-reset-storage-token-signing-key", KeyUsageType.SIGN_VERIFY);
        kmsInitialiser.createKey("alias/local-mfa-reset-jar-signing-key", KeyUsageType.SIGN_VERIFY);

        // Set up localstack SQS queues
        //
        // Without consumers for these queues these are effectively just DLQs
        // and could be replaced with a stub implementation
        var sqsInitialiser = new SqsInitialiser();
        sqsInitialiser.createQueue("local-email-queue");
        sqsInitialiser.createQueue("local-experian-phone-checker-queue");
        sqsInitialiser.createQueue("local-pending-email-check-queue");
        sqsInitialiser.createQueue("local-txma-audit-queue");

        // Set up data in the DynamoDB tables
        //
        // Tables generally initialised automatically in the 'warm up' step
        // Once we remove reliance on the client registry this can be removed as well
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
