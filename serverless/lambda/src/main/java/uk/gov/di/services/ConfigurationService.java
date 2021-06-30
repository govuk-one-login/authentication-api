package uk.gov.di.services;

import uk.gov.di.entity.NotificationType;

import java.net.URI;
import java.util.Optional;

public class ConfigurationService {

    public Optional<String> getBaseURL() {
        return Optional.ofNullable(System.getenv("BASE_URL"));
    }

    public URI getLoginURI() {
        return URI.create(System.getenv("LOGIN_URI"));
    }

    public String getRedisHost() {
        return System.getenv().getOrDefault("REDIS_HOST", "redis");
    }

    public int getRedisPort() {
        return Integer.parseInt(System.getenv().getOrDefault("REDIS_PORT", "6379"));
    }

    public boolean getUseRedisTLS() {
        return Boolean.parseBoolean(System.getenv().getOrDefault("REDIS_TLS", "false"));
    }

    public Optional<String> getRedisPassword() {
        return Optional.ofNullable(System.getenv("REDIS_PASSWORD"));
    }

    public String getEnvironment() {
        return System.getenv("ENVIRONMENT");
    }

    public long getSessionExpiry() {
        return Long.parseLong(System.getenv().getOrDefault("SESSION_EXPIRY", "1800"));
    }

    public String getNotifyApiKey() {
        return System.getenv("NOTIFY_API_KEY");
    }

    public long getEmailCodeExpiry() {
        return Long.parseLong(System.getenv().getOrDefault("EMAIL_CODE_EXPIRY", "900"));
    }

    public String getNotificationTemplateId(NotificationType notificationType) {
        switch (notificationType) {
            case VERIFY_EMAIL:
                return System.getenv("VERIFY_EMAIL_TEMPLATE_ID");
            default:
                throw new RuntimeException("NotificationType template ID does not exist");
        }
    }

    public Optional<String> getNotifyApiUrl() {
        return Optional.ofNullable(System.getenv("NOTIFY_URL"));
    }

    public String getEmailQueueUri() {
        return System.getenv("EMAIL_QUEUE_URL");
    }

    public String getAwsRegion() {
        return System.getenv("AWS_REGION");
    }

    public Optional<String> getSqsEndpointUri() {
        return Optional.ofNullable(System.getenv("SQS_ENDPOINT"));
    }

    public Optional<String> getDynamoEndpointUri() {
        return Optional.ofNullable(System.getenv("DYNAMO_ENDPOINT"));
    }
}
