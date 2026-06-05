package uk.gov.di.authentication.accountdata.services;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Optional;

public class ConfigurationService {
    private static final Logger LOG =
            LogManager.getLogger(
                    uk.gov.di.authentication.shared.services.ConfigurationService.class);

    public String getAwsRegion() {
        return System.getenv("AWS_REGION");
    }

    public String getEnvironment() {
        return System.getenv().getOrDefault("ENVIRONMENT", "test");
    }

    public Optional<String> getDynamoArnPrefix() {
        return Optional.ofNullable(System.getenv("DYNAMO_ARN_PREFIX"));
    }

    public Optional<String> getDynamoEndpointUri() {
        return Optional.ofNullable(System.getenv("DYNAMO_ENDPOINT"));
    }

    public URL getAccountDataJwksUrl() throws MalformedURLException {
        try {
            return new URL(System.getenv().get("ACCOUNT_DATA_JWKS_URL"));
        } catch (MalformedURLException e) {
            LOG.error("Invalid JWKS URL: {}", e.getMessage());
            throw new MalformedURLException(e.getMessage());
        }
    }

    public String getAuthIssuerClaim() {
        return System.getenv().getOrDefault("AUTH_ISSUER_CLAIM", "");
    }

    public String getAMCClientId() {
        return System.getenv().getOrDefault("AMC_CLIENT_ID", "");
    }

    public String getHomeClientId() {
        return System.getenv().getOrDefault("HOME_CLIENT_ID", "");
    }

    public String getAuthToAccountDataApiAudience() {
        return System.getenv().getOrDefault("AUTH_TO_ACCOUNT_DATA_API_AUDIENCE", "");
    }
}
