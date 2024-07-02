package uk.gov.di.orchestration.shared.validation;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.util.DateUtils;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.auth.PrivateKeyJWT;
import com.nimbusds.oauth2.sdk.auth.verifier.ClientAuthenticationVerifier;
import com.nimbusds.oauth2.sdk.auth.verifier.InvalidClientException;
import com.nimbusds.oauth2.sdk.id.Audience;
import uk.gov.di.orchestration.shared.api.OidcAPI;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.exceptions.TokenAuthInvalidException;
import uk.gov.di.orchestration.shared.helpers.NowHelper;
import uk.gov.di.orchestration.shared.services.DynamoClientService;

import java.util.Collections;
import java.util.Date;
import java.util.Map;
import java.util.Objects;

import static uk.gov.di.orchestration.shared.helpers.InstrumentationHelper.addAnnotation;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.CLIENT_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.attachLogFieldToLogs;

public class PrivateKeyJwtClientAuthValidator extends TokenClientAuthValidator {

    private final OidcAPI oidcApi;
    private static final String UNKNOWN_CLIENT_ID = "unknown";

    public PrivateKeyJwtClientAuthValidator(
            DynamoClientService dynamoClientService, OidcAPI oidcApi) {
        super(dynamoClientService);
        this.oidcApi = oidcApi;
    }

    @Override
    public ClientRegistry validateTokenAuthAndReturnClientRegistryIfValid(
            String requestBody, Map<String, String> requestHeaders)
            throws TokenAuthInvalidException {
        try {
            LOG.info("Validating private_key_jwt");
            var privateKeyJWT = PrivateKeyJWT.parse(requestBody);
            if (Objects.isNull(privateKeyJWT.getClientID())) {
                LOG.warn("Invalid ClientID in PrivateKeyJWT");
                throw new InvalidClientException("ClientID missing from PrivateKeyJWT");
            }
            var clientRegistry = getClientRegistryFromTokenAuth(privateKeyJWT.getClientID());
            attachLogFieldToLogs(CLIENT_ID, clientRegistry.getClientID());
            addAnnotation("client_id", clientRegistry.getClientID());
            var tokenUrl = oidcApi.tokenURI();
            if (Objects.nonNull(clientRegistry.getTokenAuthMethod())
                    && !clientRegistry
                            .getTokenAuthMethod()
                            .equals(ClientAuthenticationMethod.PRIVATE_KEY_JWT.getValue())) {
                LOG.warn("Client is not registered to use private_key_jwt");
                throw new TokenAuthInvalidException(
                        new ErrorObject(
                                OAuth2Error.INVALID_CLIENT_CODE,
                                "Client is not registered to use private_key_jwt"),
                        ClientAuthenticationMethod.PRIVATE_KEY_JWT,
                        clientRegistry.getClientID());
            }
            if (hasPrivateKeyJwtExpired(privateKeyJWT.getClientAssertion())) {
                LOG.warn("private_key_jwt has expired");
                throw new TokenAuthInvalidException(
                        new ErrorObject(
                                OAuth2Error.INVALID_GRANT_CODE, "private_key_jwt has expired"),
                        ClientAuthenticationMethod.PRIVATE_KEY_JWT,
                        clientRegistry.getClientID());
            }
            ClientAuthenticationVerifier<?> authenticationVerifier =
                    new ClientAuthenticationVerifier<>(
                            new PrivateKeyJwtAuthPublicKeySelector(
                                    clientRegistry.getPublicKey(), KeyType.RSA),
                            Collections.singleton(new Audience(tokenUrl)));
            authenticationVerifier.verify(privateKeyJWT, null, null);
            return clientRegistry;
        } catch (InvalidClientException e) {
            LOG.warn("Invalid client in private_kew_jwt", e);
            throw new TokenAuthInvalidException(
                    OAuth2Error.INVALID_CLIENT,
                    ClientAuthenticationMethod.PRIVATE_KEY_JWT,
                    UNKNOWN_CLIENT_ID);
        } catch (JOSEException e) {
            LOG.warn("Could not verify signature of private_key_jwt", e);
            throw new TokenAuthInvalidException(
                    new ErrorObject(
                            OAuth2Error.INVALID_CLIENT_CODE,
                            "Invalid signature in private_key_jwt"),
                    ClientAuthenticationMethod.PRIVATE_KEY_JWT,
                    UNKNOWN_CLIENT_ID);
        } catch (ParseException e) {
            LOG.warn("Unable to parse private_kew_jwt", e);
            throw new TokenAuthInvalidException(
                    new ErrorObject(OAuth2Error.INVALID_REQUEST_CODE, "Invalid private_key_jwt"),
                    ClientAuthenticationMethod.PRIVATE_KEY_JWT,
                    UNKNOWN_CLIENT_ID);
        }
    }

    private boolean hasPrivateKeyJwtExpired(SignedJWT signedJWT) {
        try {
            JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
            Date currentDateTime = NowHelper.now();
            if (DateUtils.isBefore(claimsSet.getExpirationTime(), currentDateTime, 30)) {
                LOG.warn(
                        "private_key_jwt has expired. Expiration time: {}. Current time: {}",
                        claimsSet.getExpirationTime(),
                        currentDateTime);
                return true;
            }
        } catch (java.text.ParseException e) {
            LOG.warn("Unable to parse private_key_jwt when checking if expired", e);
            return true;
        }
        return false;
    }
}
