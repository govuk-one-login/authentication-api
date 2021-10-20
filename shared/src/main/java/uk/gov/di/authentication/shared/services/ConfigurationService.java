package uk.gov.di.authentication.shared.services;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

public class ConfigurationService {

    private static ConfigurationService configurationService;

    public static ConfigurationService getInstance() {
        if (configurationService == null) {
            configurationService = new ConfigurationService();
        }
        return configurationService;
    }

    // Please keep the method names in alphabetical order so we can find stuff more easily.
    public long getAccessTokenExpiry() {
        return Long.parseLong(System.getenv().getOrDefault("ACCESS_TOKEN_EXPIRY", "180"));
    }

    public String getAccountManagementURI() {
        return System.getenv("ACCOUNT_MANAGEMENT_URI");
    }

    public long getAuthCodeExpiry() {
        return Long.parseLong(System.getenv().getOrDefault("AUTH_CODE_EXPIRY", "300"));
    }

    public URI getAuthCodeURI() {
        return URI.create(System.getenv().getOrDefault("AUTH_CODE_URI", "/auth-code"));
    }

    public String getAwsRegion() {
        return System.getenv("AWS_REGION");
    }

    public Optional<String> getBaseURL() {
        return Optional.ofNullable(System.getenv("BASE_URL"));
    }

    public long getCodeExpiry() {
        return Long.parseLong(System.getenv().getOrDefault("CODE_EXPIRY", "900"));
    }

    public int getCodeMaxRetries() {
        return Integer.parseInt(System.getenv().getOrDefault("CODE_MAX_RETRIES", "5"));
    }

    public int getMaxPasswordRetries() {
        return Integer.parseInt(System.getenv().getOrDefault("PASSWORD_MAX_RETRIES", "5"));
    }

    public URI getDefaultLogoutURI() {
        return URI.create(System.getenv("DEFAULT_LOGOUT_URI"));
    }

    public String getDomainName() {
        return System.getenv("DOMAIN_NAME");
    }

    public Optional<String> getDynamoEndpointUri() {
        return Optional.ofNullable(System.getenv("DYNAMO_ENDPOINT"));
    }

    public String getEmailQueueUri() {
        return System.getenv("EMAIL_QUEUE_URL");
    }

    public String getEnvironment() {
        return System.getenv("ENVIRONMENT");
    }

    public String getEventsSnsTopicArn() {
        return System.getenv("EVENTS_SNS_TOPIC_ARN");
    }

    public String getFrontendBaseUrl() {
        return System.getenv().getOrDefault("FRONTEND_BASE_URL", "");
    }

    public long getIDTokenExpiry() {
        return Long.parseLong(System.getenv().getOrDefault("ID_TOKEN_EXPIRY", "120"));
    }

    public Optional<String> getLocalstackEndpointUri() {
        return Optional.ofNullable(System.getenv("LOCALSTACK_ENDPOINT"));
    }

    public URI getLoginURI() {
        return URI.create(System.getenv("LOGIN_URI"));
    }

    public String getNotifyApiKey() {
        return System.getenv("NOTIFY_API_KEY");
    }

    public Optional<String> getNotifyApiUrl() {
        return Optional.ofNullable(System.getenv("NOTIFY_URL"));
    }

    public Optional<String> getNotifyTestPhoneNumber() {
        return Optional.ofNullable(System.getenv("NOTIFY_TEST_PHONE_NUMBER"));
    }

    public Optional<String> getPasswordPepper() {
        return Optional.ofNullable(System.getenv("PASSWORD_PEPPER"));
    }

    public String getRedisHost() {
        return System.getenv().getOrDefault("REDIS_HOST", "redis");
    }

    public Optional<String> getRedisPassword() {
        return Optional.ofNullable(System.getenv("REDIS_PASSWORD"));
    }

    public int getRedisPort() {
        return Integer.parseInt(System.getenv().getOrDefault("REDIS_PORT", "6379"));
    }

    public boolean getUseRedisTLS() {
        return Boolean.parseBoolean(System.getenv().getOrDefault("REDIS_TLS", "false"));
    }

    public String getResetPasswordRoute() {
        return System.getenv().getOrDefault("RESET_PASSWORD_ROUTE", "");
    }

    public String getSessionCookieAttributes() {
        return Optional.ofNullable(System.getenv("SESSION_COOKIE_ATTRIBUTES"))
                .orElse("Secure; HttpOnly;");
    }

    public int getSessionCookieMaxAge() {
        return Integer.parseInt(System.getenv().getOrDefault("SESSION_COOKIE_MAX_AGE", "3600"));
    }

    public long getSessionExpiry() {
        return Long.parseLong(System.getenv().getOrDefault("SESSION_EXPIRY", "3600"));
    }

    public String getSmoketestBucketName() {
        return System.getenv("SMOKETEST_SMS_BUCKET_NAME");
    }

    public URI getSkipLoginURI() {
        return URI.create(System.getenv().getOrDefault("SKIP_LOGIN_URI", "http://skip-login"));
    }

    public Optional<String> getSqsEndpointUri() {
        return Optional.ofNullable(System.getenv("SQS_ENDPOINT"));
    }

    public String getTermsAndConditionsVersion() {
        return System.getenv("TERMS_CONDITIONS_VERSION");
    }

    public Optional<String> getTestClientVerifyEmailOTP() {
        return Optional.ofNullable(System.getenv("TEST_CLIENT_VERIFY_EMAIL_OTP"));
    }

    public Optional<String> getTestClientVerifyPhoneNumberOTP() {
        return Optional.ofNullable(System.getenv("TEST_CLIENT_VERIFY_PHONE_NUMBER_OTP"));
    }

    public boolean isTestClientsEnabled() {
        return System.getenv().getOrDefault("TEST_CLIENTS_ENABLED", "false").equals("true");
    }

    public String getTokenSigningKeyAlias() {
        return System.getenv("TOKEN_SIGNING_KEY_ALIAS");
    }

    public String getAuditSigningKeyAlias() {
        return System.getenv("AUDIT_SIGNING_KEY_ALIAS");
    }

    public String getAuditStorageS3Bucket() {
        return System.getenv("AUDIT_STORAGE_S3_BUCKET");
    }

    public int getWarmupDelayMillis() {
        return Integer.parseInt(System.getenv().getOrDefault("WARMER_DELAY", "75"));
    }

    public byte[] getSalt() {
        return System.getenv().getOrDefault("SALT", "random").getBytes(StandardCharsets.UTF_8);
    }
}
