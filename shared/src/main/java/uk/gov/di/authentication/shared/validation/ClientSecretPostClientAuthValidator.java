package uk.gov.di.authentication.shared.validation;

import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.auth.ClientSecretPost;
import com.nimbusds.oauth2.sdk.auth.verifier.InvalidClientException;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.exceptions.TokenAuthInvalidException;
import uk.gov.di.authentication.shared.helpers.Argon2MatcherHelper;
import uk.gov.di.authentication.shared.services.DynamoClientService;

import java.util.Map;
import java.util.Objects;

import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.addAnnotation;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.LogFieldName.CLIENT_ID;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachLogFieldToLogs;

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
            addAnnotation("client_id", clientSecretPost.getClientID().getValue());
            var clientRegistry = getClientRegistryFromTokenAuth(clientSecretPost.getClientID());
            if (Objects.isNull(clientRegistry.getTokenAuthMethod())
                    || !clientRegistry
                            .getTokenAuthMethod()
                            .equals(ClientAuthenticationMethod.CLIENT_SECRET_POST.getValue())) {
                LOG.warn("Client is not registered to use client_secret_post");
                throw new TokenAuthInvalidException(
                        new ErrorObject(
                                OAuth2Error.INVALID_CLIENT_CODE,
                                "Client is not registered to use client_secret_post"),
                        ClientAuthenticationMethod.CLIENT_SECRET_POST,
                        clientRegistry.getClientID());
            }
            if (Objects.isNull(clientRegistry.getClientSecret())) {
                LOG.warn("No client secret registered for this client");
                throw new TokenAuthInvalidException(
                        new ErrorObject(
                                OAuth2Error.INVALID_CLIENT_CODE, "No client secret registered"),
                        ClientAuthenticationMethod.CLIENT_SECRET_POST,
                        clientRegistry.getClientID());
            }
            var validSecret =
                    Argon2MatcherHelper.matchRawStringWithEncoded(
                            clientSecretPost.getClientSecret().getValue(),
                            clientRegistry.getClientSecret());
            if (!validSecret) {
                LOG.warn("Invalid Client Secret when validating for client_secret_post");
                throw new TokenAuthInvalidException(
                        new ErrorObject(OAuth2Error.INVALID_CLIENT_CODE, "Invalid client secret"),
                        ClientAuthenticationMethod.CLIENT_SECRET_POST,
                        clientRegistry.getClientID());
            }
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
}
