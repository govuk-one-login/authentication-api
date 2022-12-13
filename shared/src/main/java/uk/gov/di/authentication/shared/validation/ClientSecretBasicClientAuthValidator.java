package uk.gov.di.authentication.shared.validation;

import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.verifier.InvalidClientException;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.exceptions.TokenAuthInvalidException;
import uk.gov.di.authentication.shared.helpers.Argon2MatcherHelper;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoClientService;

import java.util.Map;
import java.util.Objects;

import static uk.gov.di.authentication.shared.domain.RequestHeaders.AUTHORIZATION_HEADER;
import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.addAnnotation;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.LogFieldName.CLIENT_ID;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachLogFieldToLogs;
import static uk.gov.di.authentication.shared.helpers.RequestHeaderHelper.getHeaderValueFromHeaders;

public class ClientSecretBasicClientAuthValidator extends TokenClientAuthValidator {

    private final ConfigurationService configurationService;

    public ClientSecretBasicClientAuthValidator(
            DynamoClientService dynamoClientService, ConfigurationService configurationService) {
        super(dynamoClientService);
        this.configurationService = configurationService;
    }

    @Override
    public ClientRegistry validateTokenAuthAndReturnClientRegistryIfValid(
            String requestBody, Map<String, String> requestHeaders)
            throws TokenAuthInvalidException {
        try {
            LOG.info("Validating client_secret_basic");
            var authorizationHeader =
                    getHeaderValueFromHeaders(
                            requestHeaders,
                            AUTHORIZATION_HEADER,
                            configurationService.getHeadersCaseInsensitive());
            var clientSecretBasic = ClientSecretBasic.parse(authorizationHeader);
            attachLogFieldToLogs(CLIENT_ID, clientSecretBasic.getClientID().getValue());
            addAnnotation("client_id", clientSecretBasic.getClientID().getValue());
            var clientRegistry = getClientRegistryFromTokenAuth(clientSecretBasic.getClientID());

            if (Objects.isNull(clientRegistry.getTokenAuthMethod())
                    || !clientRegistry
                            .getTokenAuthMethod()
                            .equals(ClientAuthenticationMethod.CLIENT_SECRET_BASIC.getValue())) {
                LOG.warn("Client is not registered to use client_secret_basic");
                throw new TokenAuthInvalidException(
                        new ErrorObject(
                                OAuth2Error.INVALID_CLIENT_CODE,
                                "Client is not registered to use client_secret_basic"),
                        ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
                        clientRegistry.getClientID());
            }
            if (Objects.isNull(clientRegistry.getClientSecret())) {
                LOG.warn("No client secret registered for this client");
                throw new TokenAuthInvalidException(
                        new ErrorObject(
                                OAuth2Error.INVALID_CLIENT_CODE, "No client secret registered"),
                        ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
                        clientRegistry.getClientID());
            }
            var validSecret =
                    Argon2MatcherHelper.matchRawStringWithEncoded(
                            clientSecretBasic.getClientSecret().getValue(),
                            clientRegistry.getClientSecret());
            if (!validSecret) {
                LOG.warn("Invalid Client Secret when validating for client_secret_basic");
                throw new TokenAuthInvalidException(
                        new ErrorObject(OAuth2Error.INVALID_CLIENT_CODE, "Invalid client secret"),
                        ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
                        clientRegistry.getClientID());
            }
            LOG.info("client_secret_basic is valid");
            return clientRegistry;
        } catch (ParseException e) {
            LOG.warn("Could not parse client_secret_basic");
            throw new TokenAuthInvalidException(
                    OAuth2Error.INVALID_REQUEST,
                    ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
                    "unknown");
        } catch (InvalidClientException e) {
            LOG.warn("Invalid client_id in client_secret_basic");
            throw new TokenAuthInvalidException(
                    OAuth2Error.INVALID_CLIENT,
                    ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
                    "unknown");
        }
    }
}
