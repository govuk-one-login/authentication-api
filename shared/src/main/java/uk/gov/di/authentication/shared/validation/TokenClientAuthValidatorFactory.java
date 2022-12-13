package uk.gov.di.authentication.shared.validation;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoClientService;

import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import static uk.gov.di.authentication.shared.domain.RequestHeaders.AUTHORIZATION_HEADER;
import static uk.gov.di.authentication.shared.helpers.RequestBodyHelper.parseRequestBody;
import static uk.gov.di.authentication.shared.helpers.RequestHeaderHelper.getHeaderValueFromHeaders;

public class TokenClientAuthValidatorFactory {

    private final ConfigurationService configurationService;
    private final DynamoClientService dynamoClientService;
    private static final Logger LOG = LogManager.getLogger(TokenClientAuthValidatorFactory.class);

    public TokenClientAuthValidatorFactory(
            ConfigurationService configurationService, DynamoClientService dynamoClientService) {
        this.configurationService = configurationService;
        this.dynamoClientService = dynamoClientService;
    }

    public Optional<TokenClientAuthValidator> getTokenAuthenticationValidator(
            String inputBody, Map<String, String> requestHeaders) {
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
        var authorizationHeader =
                getHeaderValueFromHeaders(
                        requestHeaders,
                        AUTHORIZATION_HEADER,
                        configurationService.getHeadersCaseInsensitive());
        if (Objects.nonNull(authorizationHeader)
                && authorizationHeader.startsWith("Basic")
                && configurationService.isClientSecretSupported()) {
            LOG.info("Client auth method is: client_secret_basic");
            return Optional.of(
                    new ClientSecretBasicClientAuthValidator(
                            dynamoClientService, configurationService));
        }
        return Optional.empty();
    }
}
