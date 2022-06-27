package uk.gov.di.authentication.audit.configuration;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;

import java.util.Optional;

import static java.util.Objects.isNull;

public class TXMAConfiguration {

    private static final Logger LOG = LogManager.getLogger(TXMAConfiguration.class);

    private final SecretsManagerClient secretsManagerClient;

    private String cachedObfuscationHMACSecret;

    public TXMAConfiguration() {
        this.secretsManagerClient = SecretsManagerClient.builder().build();
    }

    public TXMAConfiguration(SecretsManagerClient secretsManagerClient) {
        this.secretsManagerClient = secretsManagerClient;
    }

    public Optional<String> getObfuscationHMACSecretArn() {
        var arn = System.getenv().get("TXMA_OBFUSCATION_SECRET_ARN");
        if (isNull(arn) || arn.isBlank()) {
            return Optional.empty();
        }
        return Optional.of(arn);
    }

    public String getObfuscationHMACSecret() {
        if (isNull(cachedObfuscationHMACSecret)) {
            cachedObfuscationHMACSecret =
                    getObfuscationHMACSecretArn()
                            .map(
                                    secretArn -> {
                                        GetSecretValueRequest getSecretValueRequest =
                                                GetSecretValueRequest.builder()
                                                        .secretId(secretArn)
                                                        .build();
                                        try {
                                            var getSecretValueResponse =
                                                    secretsManagerClient.getSecretValue(
                                                            getSecretValueRequest);
                                            return getSecretValueResponse.secretString();
                                        } catch (Exception e) {
                                            LOG.error("Could not get secret from TXMA", e);
                                            throw new RuntimeException(
                                                    "Invalid configuration. HMAC secret key cannot be read.",
                                                    e);
                                        }
                                    })
                            .orElseThrow(
                                    () ->
                                            new RuntimeException(
                                                    "Invalid configuration. HMAC secret key not specified."));
        }
        return cachedObfuscationHMACSecret;
    }
}
