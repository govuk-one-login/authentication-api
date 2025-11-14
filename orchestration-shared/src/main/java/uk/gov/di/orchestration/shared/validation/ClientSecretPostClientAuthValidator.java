package uk.gov.di.orchestration.shared.validation;

import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.auth.ClientSecretPost;
import com.nimbusds.oauth2.sdk.auth.verifier.InvalidClientException;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.exceptions.TokenAuthInvalidException;
import uk.gov.di.orchestration.shared.helpers.Argon2MatcherHelper;
import uk.gov.di.orchestration.shared.services.DynamoClientService;

import java.util.Map;
import java.util.Objects;

import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.CLIENT_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.attachLogFieldToLogs;

public class ClientSecretPostClientAuthValidator extends TokenClientAuthValidator {

    public ClientSecretPostClientAuthValidator(DynamoClientService dynamoClientService) {
        super(dynamoClientService);
    }

    @Override
    public ClientRegistry validateTokenAuthAndReturnClientRegistryIfValid(
            String requestBody, Map<String, String> requestHeaders)
            throws TokenAuthInvalidException {
        try {
            LOG.info("Validating client_secret_post");
            var clientSecretPost = ClientSecretPost.parse(requestBody);
            attachLogFieldToLogs(CLIENT_ID, clientSecretPost.getClientID().getValue());

            var clientRegistry = getClientRegistryFromTokenAuth(clientSecretPost.getClientID());
            validateTokenAuthMethod(clientRegistry);
            validateSecret(clientSecretPost.getClientSecret().getValue(), clientRegistry);
            LOG.info("client_secret_post is valid");
            return clientRegistry;
        } catch (InvalidClientException e) {
            LOG.warn("Invalid Client when validating client_secret_post", e);
            throw new TokenAuthInvalidException(
                    OAuth2Error.INVALID_CLIENT,
                    ClientAuthenticationMethod.CLIENT_SECRET_POST,
                    "unknown");
        } catch (ParseException e) {
            LOG.warn("Could not parse client_secret_post");
            throw new TokenAuthInvalidException(
                    new ErrorObject(OAuth2Error.INVALID_REQUEST_CODE, "Invalid client secret"),
                    ClientAuthenticationMethod.CLIENT_SECRET_POST,
                    "unknown");
        }
    }

    private void validateTokenAuthMethod(ClientRegistry clientRegistry)
            throws TokenAuthInvalidException {
        if (Objects.isNull(clientRegistry.getTokenAuthMethod())
                || !clientRegistry
                        .getTokenAuthMethod()
                        .equals(ClientAuthenticationMethod.CLIENT_SECRET_POST.getValue())) {
            LOG.warn("Client is not registered to use client_secret_post");
            throw generateExceptionWithInvalidClientCode(
                    "Client is not registered to use client_secret_post",
                    clientRegistry.getClientID());
        }
        if (Objects.isNull(clientRegistry.getClientSecret())) {
            LOG.warn("No client secret registered for this client");
            throw generateExceptionWithInvalidClientCode(
                    "No client secret registered", clientRegistry.getClientID());
        }
    }

    private void validateSecret(String requestSecret, ClientRegistry clientRegistry)
            throws TokenAuthInvalidException {
        var validSecret =
                Argon2MatcherHelper.matchRawStringWithEncoded(
                        requestSecret, clientRegistry.getClientSecret());
        if (!validSecret) {
            LOG.warn("Invalid Client Secret when validating for client_secret_post");
            throw generateExceptionWithInvalidClientCode(
                    "Invalid client secret", clientRegistry.getClientID());
        }
    }

    private TokenAuthInvalidException generateExceptionWithInvalidClientCode(
            String description, String clientID) {
        return new TokenAuthInvalidException(
                new ErrorObject(OAuth2Error.INVALID_CLIENT_CODE, description),
                ClientAuthenticationMethod.CLIENT_SECRET_POST,
                clientID);
    }
}
