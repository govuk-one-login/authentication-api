package uk.gov.di.authentication.audit.configuration;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.DecryptionFailureException;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;
import software.amazon.awssdk.services.secretsmanager.model.InternalServiceErrorException;
import software.amazon.awssdk.services.secretsmanager.model.InvalidParameterException;
import software.amazon.awssdk.services.secretsmanager.model.InvalidRequestException;
import software.amazon.awssdk.services.secretsmanager.model.ResourceNotFoundException;

import java.util.Optional;

import static java.util.Objects.isNull;

public class TXMAConfiguration {

    private static final Logger LOG = LogManager.getLogger(TXMAConfiguration.class);

    private final SecretsManagerClient secretsManagerClient;

    private Optional<String> cachedObfuscationHMACSecret;

    public TXMAConfiguration() {
        this.secretsManagerClient = SecretsManagerClient.builder().build();
    }

    public TXMAConfiguration(SecretsManagerClient secretsManagerClient) {
        this.secretsManagerClient = secretsManagerClient;
    }

    public Optional<String> getObfuscationHMACSecretArn() {
        return Optional.ofNullable(System.getenv().get("TXMA_OBFUSCATION_SECRET_ARN"));
    }

    public Optional<String> getObfuscationHMACSecret() {
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
                                        } catch (DecryptionFailureException
                                                | InternalServiceErrorException
                                                | InvalidParameterException
                                                | InvalidRequestException
                                                | ResourceNotFoundException e) {
                                            LOG.error("Could not get secret from TXMA", e);
                                            return null;
                                        }
                                    });
        }
        return cachedObfuscationHMACSecret;
    }
}
