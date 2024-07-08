package uk.gov.di.orchestration.shared.validation;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.orchestration.shared.services.ClientSignatureValidationService;
import uk.gov.di.orchestration.shared.services.DynamoClientService;

import java.util.Map;
import java.util.Objects;
import java.util.Optional;

public class TokenClientAuthValidatorFactory {
    private final DynamoClientService dynamoClientService;
    private final ClientSignatureValidationService clientSignatureValidationService;
    private static final Logger LOG = LogManager.getLogger(TokenClientAuthValidatorFactory.class);

    public TokenClientAuthValidatorFactory(
            DynamoClientService dynamoClientService,
            ClientSignatureValidationService clientSignatureValidationService) {
        this.clientSignatureValidationService = clientSignatureValidationService;
        this.dynamoClientService = dynamoClientService;
    }

    public Optional<TokenClientAuthValidator> getTokenAuthenticationValidator(
            Map<String, String> requestBody) {
        LOG.info("Getting ClientAuthenticationMethod from request");

        if (requestBody.containsKey("client_assertion")
                && requestBody.containsKey("client_assertion_type")) {
            LOG.info("Client auth method is: private_key_jwt");
            checkAssertionType(requestBody);
            return Optional.of(
                    new PrivateKeyJwtClientAuthValidator(
                            dynamoClientService, clientSignatureValidationService));
        }

        if (requestBody.containsKey("client_secret") && requestBody.containsKey("client_id")) {
            LOG.info("Client auth method is: client_secret_post");
            return Optional.of(new ClientSecretPostClientAuthValidator(dynamoClientService));
        }
        return Optional.empty();
    }

    private static void checkAssertionType(Map<String, String> requestBody) {
        if (!Objects.equals(
                requestBody.get("client_assertion_type"),
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")) {
            LOG.warn(
                    "Incorrect client assertion type used: {} for redirect_uri {}",
                    requestBody.get("client_assertion_type"),
                    requestBody.getOrDefault("redirect_uri", "<not present>"));
        }
    }
}
