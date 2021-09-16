package uk.gov.di.authentication.shared.services;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

public class ConfigurationService {

    // Please keep the method names in alphabetical order so we can find stuff more easily.

    public long getAccessTokenExpiry() {
        return Long.parseLong(System.getenv().getOrDefault("ACCESS_TOKEN_EXPIRY", "180"));
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

    public String getSessionCookieAttributes() {
        return Optional.ofNullable(System.getenv("SESSION_COOKIE_ATTRIBUTES"))
                .orElse("Secure; HttpOnly;");
    }

    public int getSessionCookieMaxAge() {
        return Integer.parseInt(System.getenv().getOrDefault("SESSION_COOKIE_MAX_AGE", "1800"));
    }

    public long getSessionExpiry() {
        return Long.parseLong(System.getenv().getOrDefault("SESSION_EXPIRY", "1800"));
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

    public String getTokenSigningKeyAlias() {
        return System.getenv("TOKEN_SIGNING_KEY_ALIAS");
    }

    public int getWarmupDelayMillis() {
        return Integer.parseInt(System.getenv().getOrDefault("WARMER_DELAY", "75"));
    }

    public byte[] getSalt() {
        return System.getenv().getOrDefault("SALT", "random").getBytes(StandardCharsets.UTF_8);
    }
}
