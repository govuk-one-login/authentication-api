package uk.gov.di.orchestration.shared.validation;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.DynamoClientService;

import java.util.Optional;

import static uk.gov.di.orchestration.shared.helpers.RequestBodyHelper.parseRequestBody;

public class TokenClientAuthValidatorFactory {

    private final ConfigurationService configurationService;
    private final DynamoClientService dynamoClientService;
    private static final Logger LOG = LogManager.getLogger(TokenClientAuthValidatorFactory.class);

    public TokenClientAuthValidatorFactory(
            ConfigurationService configurationService, DynamoClientService dynamoClientService) {
        this.configurationService = configurationService;
        this.dynamoClientService = dynamoClientService;
    }

    public Optional<TokenClientAuthValidator> getTokenAuthenticationValidator(String inputBody) {
        LOG.info("Getting ClientAuthenticationMethod from request");
        LOG.info("ClientSecretSupport: {}", configurationService.isClientSecretSupported());
        var requestBody = parseRequestBody(inputBody);
        if (requestBody.containsKey("client_assertion")
                && requestBody.containsKey("client_assertion_type")) {
            LOG.info("Client auth method is: private_key_jwt");
            return Optional.of(
                    new PrivateKeyJwtClientAuthValidator(
                            dynamoClientService, configurationService));
        }
        if (requestBody.containsKey("client_secret")
                && requestBody.containsKey("client_id")
                && configurationService.isClientSecretSupported()) {
            LOG.info("Client auth method is: client_secret_post");
            return Optional.of(new ClientSecretPostClientAuthValidator(dynamoClientService));
        }
        return Optional.empty();
    }
}
