package uk.gov.di.authentication.local;

import software.amazon.awssdk.services.kms.model.KeyUsageType;
import uk.gov.di.authentication.local.initialisers.DynamoDbInitialiser;
import uk.gov.di.authentication.local.initialisers.KmsInitialiser;
import uk.gov.di.authentication.local.initialisers.ParameterInitialiser;
import uk.gov.di.authentication.local.initialisers.SqsInitialiser;
import uk.gov.di.authentication.shared.entity.AccessTokenStore;
import uk.gov.di.authentication.shared.entity.AccountModifiers;
import uk.gov.di.authentication.shared.entity.AuthCodeStore;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.CommonPassword;
import uk.gov.di.authentication.shared.entity.UserCredentials;
import uk.gov.di.authentication.shared.entity.UserProfile;

import static java.lang.String.valueOf;

public class App {
    public static void main(String[] args) throws Exception {
        // Once we move off Redis it might be easier just to bypass this a different way
        var parameterInitialiser = new ParameterInitialiser();
        parameterInitialiser.setParam("local-session-redis-master-host", "host.docker.internal");
        parameterInitialiser.setParam("local-session-redis-port", valueOf(6379));
        parameterInitialiser.setParam("local-session-redis-tls", valueOf(false));
        parameterInitialiser.setParam("local-password-pepper", "pepper");
        parameterInitialiser.setParam("local-notify-callback-bearer-token", "notify-test-@bearer-token");

        var kmsInitialiser = new KmsInitialiser();
        kmsInitialiser.createKey("token-signing-key", KeyUsageType.SIGN_VERIFY);
        kmsInitialiser.createKey("mfa-reset-storage-token-signing-key", KeyUsageType.SIGN_VERIFY);
        kmsInitialiser.createKey("mfa-reset-jar-signing-key", KeyUsageType.SIGN_VERIFY);

        var sqsInitialiser = new SqsInitialiser();
        sqsInitialiser.createQueue("local-txma-audit-queue");
        sqsInitialiser.createQueue("local-email-queue");
        sqsInitialiser.createQueue("local-pending-email-check-queue");
        sqsInitialiser.createQueue("local-experian-phone-checker-queue");

        var dynamoInitialiser = new DynamoDbInitialiser();
        dynamoInitialiser.createTable("local-user-credentials", UserCredentials.class);
        dynamoInitialiser.createTable("local-user-profile", UserProfile.class);
        dynamoInitialiser.createTable("local-client-registry", ClientRegistry.class);
        dynamoInitialiser.createTable("local-auth-session", AuthSessionItem.class);
        dynamoInitialiser.createTable("local-account-modifiers", AccountModifiers.class);
        dynamoInitialiser.createTable("local-common-passwords", CommonPassword.class);
        dynamoInitialiser.createTable("local-auth-code-store", AuthCodeStore.class);
        dynamoInitialiser.createTable("local-access-token-store", AccessTokenStore.class);
        // Could/should we handle DynamoDB the same way? Might make sense

        new LocalAuthApi();
    }
}
