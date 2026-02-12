package uk.gov.di.authentication.external.validators;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.auth.PrivateKeyJWT;
import com.nimbusds.oauth2.sdk.auth.verifier.ClientAuthenticationVerifier;
import com.nimbusds.oauth2.sdk.auth.verifier.InvalidClientException;
import com.nimbusds.oauth2.sdk.id.Audience;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.shared.exceptions.TokenAuthInvalidException;
import uk.gov.di.authentication.shared.validation.PrivateKeyJwtAuthPublicKeySelector;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

public class TokenRequestValidator {
    private static final Logger LOG = LogManager.getLogger(TokenRequestValidator.class);
    private final String redirectUri;
    private final String clientId;

    public TokenRequestValidator(String redirectUri, String clientId) {
        this.redirectUri = redirectUri;
        this.clientId = clientId;
    }

    public Optional<ErrorObject> validatePlaintextParams(Map<String, String> requestParameters) {
        if (Objects.isNull(requestParameters)) {
            return invalidRequestCode("Request requires query parameters");
        }

        if (!requestParameters.containsKey("grant_type")) {
            return invalidRequestCode("Request is missing grant_type parameter");
        }

        if (!"authorization_code".equals(requestParameters.get("grant_type"))) {
            return invalidRequestCode("Request has invalid grant_type parameter");
        }

        if (!requestParameters.containsKey("code") || requestParameters.get("code") == null) {
            return invalidRequestCode("Request is missing code parameter");
        }

        if (!requestParameters.containsKey("redirect_uri")) {
            return invalidRequestCode("Request is missing redirect_uri parameter");
        }

        if (!redirectUri.equals(requestParameters.get("redirect_uri"))) {
            return invalidRequestCode("Request redirect_uri is not the permitted redirect_uri");
        }

        if (!requestParameters.containsKey("client_id")) {
            return invalidRequestCode("Request is missing client_id parameter");
        }

        if (!clientId.equals(requestParameters.get("client_id"))) {
            return invalidRequestCode("Request client_id is not the permitted client_id");
        }

        return Optional.empty();
    }

    private static Optional<ErrorObject> invalidRequestCode(String description) {
        return Optional.of(new ErrorObject(OAuth2Error.INVALID_REQUEST_CODE, description));
    }

    public void validatePrivateKeyJwtClientAuth(
            PrivateKeyJWT privateKeyJWT, Set<Audience> expectedAudience, List<String> publicKeys)
            throws TokenAuthInvalidException {
        try {
            ClientAuthenticationVerifier<?> signatureVerifier =
                    new ClientAuthenticationVerifier<>(
                            new PrivateKeyJwtAuthPublicKeySelector(publicKeys, KeyType.EC),
                            expectedAudience);
            signatureVerifier.verify(privateKeyJWT, null, null);
        } catch (InvalidClientException e) {
            LOG.warn("Invalid client in private_key_jwt", e);
            throw new TokenAuthInvalidException(
                    OAuth2Error.INVALID_CLIENT, ClientAuthenticationMethod.PRIVATE_KEY_JWT, "tbc");
        } catch (JOSEException e) {
            LOG.warn("Could not verify signature of private_key_jwt", e);
            throw new TokenAuthInvalidException(
                    new ErrorObject(
                            OAuth2Error.INVALID_CLIENT_CODE,
                            "Invalid signature in private_key_jwt"),
                    ClientAuthenticationMethod.PRIVATE_KEY_JWT,
                    "tbc");
        }
    }
}
