package uk.gov.di.authentication.shared.validation;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.util.DateUtils;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.auth.PrivateKeyJWT;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.auth.verifier.ClientAuthenticationVerifier;
import com.nimbusds.oauth2.sdk.auth.verifier.ClientCredentialsSelector;
import com.nimbusds.oauth2.sdk.auth.verifier.InvalidClientException;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.ClientID;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.exceptions.TokenAuthInvalidException;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoClientService;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import static uk.gov.di.authentication.shared.helpers.ConstructUriHelper.buildURI;
import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.addAnnotation;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.LogFieldName.CLIENT_ID;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachLogFieldToLogs;

public class PrivateKeyJwtClientAuthValidator extends TokenClientAuthValidator {

    private final ConfigurationService configurationService;
    private static final String TOKEN_PATH = "token";
    private static final String UNKNOWN_CLIENT_ID = "unknown";

    public PrivateKeyJwtClientAuthValidator(
            DynamoClientService dynamoClientService, ConfigurationService configurationService) {
        super(dynamoClientService);
        this.configurationService = configurationService;
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
            var tokenUrl =
                    buildURI(configurationService.getOidcApiBaseURL().orElseThrow(), TOKEN_PATH)
                            .toString();
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
                            generateClientCredentialsSelector(clientRegistry.getPublicKey()),
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

    private ClientCredentialsSelector<?> generateClientCredentialsSelector(String publicKey) {
        return new ClientCredentialsSelector<>() {
            @Override
            public List<Secret> selectClientSecrets(
                    ClientID claimedClientID,
                    ClientAuthenticationMethod authMethod,
                    com.nimbusds.oauth2.sdk.auth.verifier.Context context) {
                return Collections.emptyList();
            }

            @Override
            public List<PublicKey> selectPublicKeys(
                    ClientID claimedClientID,
                    ClientAuthenticationMethod authMethod,
                    JWSHeader jwsHeader,
                    boolean forceRefresh,
                    com.nimbusds.oauth2.sdk.auth.verifier.Context context) {

                byte[] decodedKey = Base64.getMimeDecoder().decode(publicKey);
                try {
                    X509EncodedKeySpec x509publicKey = new X509EncodedKeySpec(decodedKey);
                    KeyFactory kf = KeyFactory.getInstance(KeyType.RSA.getValue());
                    return Collections.singletonList(kf.generatePublic(x509publicKey));
                } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
                    LOG.error("Exception when selecting public key", e);
                    throw new RuntimeException(e);
                }
            }
        };
    }
}
