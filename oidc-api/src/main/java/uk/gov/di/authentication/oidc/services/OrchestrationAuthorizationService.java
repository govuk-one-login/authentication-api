package uk.gov.di.authentication.oidc.services;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.impl.ECDSA;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ResponseMode;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import com.nimbusds.openid.connect.sdk.OIDCClaimsRequest;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSetRequest;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.model.SignRequest;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;
import uk.gov.di.authentication.oidc.entity.AuthRequestError;
import uk.gov.di.authentication.oidc.exceptions.InvalidJWEException;
import uk.gov.di.authentication.oidc.exceptions.InvalidPublicKeyException;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.ClientType;
import uk.gov.di.authentication.shared.entity.CustomScopeValue;
import uk.gov.di.authentication.shared.entity.ValidClaims;
import uk.gov.di.authentication.shared.entity.ValidScopes;
import uk.gov.di.authentication.shared.entity.VectorOfTrust;
import uk.gov.di.authentication.shared.exceptions.ClientNotFoundException;
import uk.gov.di.authentication.shared.exceptions.ClientRegistryValidationException;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoClientService;
import uk.gov.di.authentication.shared.services.KmsConnectionService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;

import java.net.URI;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import static com.nimbusds.oauth2.sdk.ResponseType.CODE;
import static java.lang.String.format;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.LogFieldName.CLIENT_ID;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachLogFieldToLogs;

public class OrchestrationAuthorizationService {

    public static final String VTR_PARAM = "vtr";
    public static final String AUTHENTICATION_STATE_STORAGE_PREFIX = "auth-state:";
    private static final JWSAlgorithm SIGNING_ALGORITHM = JWSAlgorithm.ES256;
    private final ConfigurationService configurationService;
    private final DynamoClientService dynamoClientService;
    private final IPVCapacityService ipvCapacityService;
    private final KmsConnectionService kmsConnectionService;
    private final RedisConnectionService redisConnectionService;
    private static final Logger LOG = LogManager.getLogger(OrchestrationAuthorizationService.class);

    public OrchestrationAuthorizationService(
            ConfigurationService configurationService,
            DynamoClientService dynamoClientService,
            IPVCapacityService ipvCapacityService,
            KmsConnectionService kmsConnectionService,
            RedisConnectionService redisConnectionService) {
        this.configurationService = configurationService;
        this.dynamoClientService = dynamoClientService;
        this.ipvCapacityService = ipvCapacityService;
        this.kmsConnectionService = kmsConnectionService;
        this.redisConnectionService = redisConnectionService;
    }

    public OrchestrationAuthorizationService(ConfigurationService configurationService) {
        this(
                configurationService,
                new DynamoClientService(configurationService),
                new IPVCapacityService(configurationService),
                new KmsConnectionService(configurationService),
                new RedisConnectionService(configurationService));
    }

    public boolean isClientRedirectUriValid(ClientID clientID, URI redirectURI)
            throws ClientNotFoundException {
        Optional<ClientRegistry> client = dynamoClientService.getClient(clientID.toString());
        if (client.isEmpty()) {
            throw new ClientNotFoundException(clientID.toString());
        }
        return client.get().getRedirectUrls().contains(redirectURI.toString());
    }

    public AuthenticationSuccessResponse generateSuccessfulAuthResponse(
            AuthenticationRequest authRequest,
            AuthorizationCode authorizationCode,
            URI redirectUri,
            State state) {

        LOG.info("Generating Successful Auth Response");
        return new AuthenticationSuccessResponse(
                redirectUri,
                authorizationCode,
                null,
                null,
                state,
                null,
                authRequest.getResponseMode());
    }

    public Optional<AuthRequestError> validateAuthRequest(
            AuthenticationRequest authRequest, boolean isNonceRequired) {
        var clientId = authRequest.getClientID().toString();

        attachLogFieldToLogs(CLIENT_ID, clientId);

        Optional<ClientRegistry> client = dynamoClientService.getClient(clientId);

        if (client.isEmpty()) {
            var errorMsg = "No Client found with given ClientID";
            LOG.warn(errorMsg);
            throw new ClientRegistryValidationException(errorMsg);
        }

        if (!client.get().getRedirectUrls().contains(authRequest.getRedirectionURI().toString())) {
            LOG.warn("Invalid Redirect URI in request {}", authRequest.getRedirectionURI());
            throw new ClientRegistryValidationException(
                    format(
                            "Invalid Redirect in request %s",
                            authRequest.getRedirectionURI().toString()));
        }
        var redirectURI = authRequest.getRedirectionURI();
        if (authRequest.getRequestURI() != null) {
            LOG.error("Request URI is not supported");
            return Optional.of(
                    new AuthRequestError(OAuth2Error.REQUEST_URI_NOT_SUPPORTED, redirectURI));
        }
        if (authRequest.getRequestObject() != null) {
            LOG.error("Request object not expected here");
            return Optional.of(
                    new AuthRequestError(OAuth2Error.REQUEST_NOT_SUPPORTED, redirectURI));
        }
        if (!authRequest.getResponseType().toString().equals(ResponseType.CODE.toString())) {
            LOG.error(
                    "Unsupported responseType included in request. Expected responseType of code");
            return Optional.of(
                    new AuthRequestError(OAuth2Error.UNSUPPORTED_RESPONSE_TYPE, redirectURI));
        }
        if (!areScopesValid(authRequest.getScope().toStringList(), client.get())) {
            return Optional.of(new AuthRequestError(OAuth2Error.INVALID_SCOPE, redirectURI));
        }
        if (!areClaimsValid(authRequest.getOIDCClaims(), client.get())) {
            return Optional.of(
                    new AuthRequestError(
                            new ErrorObject(
                                    OAuth2Error.INVALID_REQUEST_CODE,
                                    "Request contains invalid claims"),
                            redirectURI));
        }
        if (authRequest.getNonce() == null && isNonceRequired) {
            LOG.error("Nonce is missing from authRequest");
            return Optional.of(
                    new AuthRequestError(
                            new ErrorObject(
                                    OAuth2Error.INVALID_REQUEST_CODE,
                                    "Request is missing nonce parameter"),
                            redirectURI));
        }
        if (authRequest.getState() == null) {
            LOG.error("State is missing from authRequest");
            return Optional.of(
                    new AuthRequestError(
                            new ErrorObject(
                                    OAuth2Error.INVALID_REQUEST_CODE,
                                    "Request is missing state parameter"),
                            redirectURI));
        }
        List<String> authRequestVtr = authRequest.getCustomParameter(VTR_PARAM);
        try {
            var vectorOfTrust = VectorOfTrust.parseFromAuthRequestAttribute(authRequestVtr);
            if (vectorOfTrust.containsLevelOfConfidence()
                    && !ipvCapacityService.isIPVCapacityAvailable()
                    && !client.get().isTestClient()) {
                return Optional.of(
                        new AuthRequestError(OAuth2Error.TEMPORARILY_UNAVAILABLE, redirectURI));
            }
        } catch (IllegalArgumentException e) {
            LOG.error(
                    "vtr in AuthRequest is not valid. vtr in request: {}. IllegalArgumentException: {}",
                    authRequestVtr,
                    e);
            return Optional.of(
                    new AuthRequestError(
                            new ErrorObject(
                                    OAuth2Error.INVALID_REQUEST_CODE, "Request vtr not valid"),
                            redirectURI));
        }
        return Optional.empty();
    }

    public EncryptedJWT getSignedAndEncryptedJWT(JWTClaimsSet jwtClaimsSet) {
        var signedJwt = getSignedJWT(jwtClaimsSet);
        return encryptJWT(signedJwt);
    }

    public SignedJWT getSignedJWT(JWTClaimsSet jwtClaimsSet) {
        LOG.info("Generating signed and encrypted JWT");
        var jwsHeader = new JWSHeader(SIGNING_ALGORITHM);

        var encodedHeader = jwsHeader.toBase64URL();
        var encodedClaims = Base64URL.encode(jwtClaimsSet.toString());
        var message = encodedHeader + "." + encodedClaims;
        var signRequest =
                SignRequest.builder()
                        .message(SdkBytes.fromByteArray(message.getBytes()))
                        .keyId(
                                configurationService
                                        .getOrchestrationToAuthenticationTokenSigningKeyAlias())
                        .signingAlgorithm(SigningAlgorithmSpec.ECDSA_SHA_256)
                        .build();
        try {
            LOG.info("Signing request JWT");
            var signResult = kmsConnectionService.sign(signRequest);
            LOG.info("Request JWT has been signed successfully");
            var signature =
                    Base64URL.encode(
                                    ECDSA.transcodeSignatureToConcat(
                                            signResult.signature().asByteArray(),
                                            ECDSA.getSignatureByteArrayLength(SIGNING_ALGORITHM)))
                            .toString();
            return SignedJWT.parse(message + "." + signature);
        } catch (ParseException | JOSEException e) {
            LOG.error("Error when generating SignedJWT", e);
            throw new InvalidJWEException("Error when generating SignedJWT", e);
        }
    }

    private EncryptedJWT encryptJWT(SignedJWT signedJWT) {
        try {
            LOG.info("Encrypting SignedJWT");
            var publicEncryptionKey = getPublicKey();
            var jweObject =
                    new JWEObject(
                            new JWEHeader.Builder(
                                            JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
                                    .contentType("JWT")
                                    .build(),
                            new Payload(signedJWT));
            jweObject.encrypt(new RSAEncrypter(publicEncryptionKey));
            LOG.info("SignedJWT has been successfully encrypted");
            return EncryptedJWT.parse(jweObject.serialize());
        } catch (JOSEException e) {
            LOG.error("Error when encrypting SignedJWT", e);
            throw new InvalidJWEException("Error when encrypting SignedJWT", e);
        } catch (ParseException e) {
            LOG.error("Error when parsing JWE object to EncryptedJWT", e);
            throw new InvalidJWEException("Error when parsing JWE object to EncryptedJWT", e);
        }
    }

    private RSAPublicKey getPublicKey() {
        try {
            LOG.info("Getting Orchestration to Authentication Encryption Public Key");
            var orchToAuthEncryptionPublicKey =
                    configurationService.getOrchestrationToAuthenticationEncryptionPublicKey();
            return new RSAKey.Builder(
                            (RSAKey) JWK.parseFromPEMEncodedObjects(orchToAuthEncryptionPublicKey))
                    .build()
                    .toRSAPublicKey();
        } catch (JOSEException e) {
            LOG.error("Error parsing the public key to RSAPublicKey", e);
            throw new InvalidPublicKeyException("Error parsing the public key to RSAPublicKey", e);
        }
    }

    public AuthenticationErrorResponse generateAuthenticationErrorResponse(
            AuthenticationRequest authRequest,
            ErrorObject errorObject,
            URI redirectUri,
            State state) {

        return generateAuthenticationErrorResponse(
                redirectUri, state, authRequest.getResponseMode(), errorObject);
    }

    public AuthenticationErrorResponse generateAuthenticationErrorResponse(
            URI redirectUri, State state, ResponseMode responseMode, ErrorObject errorObject) {
        LOG.info("Generating Authentication Error Response");
        return new AuthenticationErrorResponse(redirectUri, errorObject, state, responseMode);
    }

    public VectorOfTrust getEffectiveVectorOfTrust(AuthenticationRequest authenticationRequest) {
        return VectorOfTrust.parseFromAuthRequestAttribute(
                authenticationRequest.getCustomParameter(VTR_PARAM));
    }

    private boolean areScopesValid(List<String> scopes, ClientRegistry clientRegistry) {
        for (String scope : scopes) {
            if (ValidScopes.getAllValidScopes().stream().noneMatch(t -> t.equals(scope))) {
                LOG.error(
                        "Scopes have been requested which are not yet supported. Scopes in request: {}",
                        scopes);
                return false;
            }
        }
        if (!clientRegistry.getScopes().containsAll(scopes)) {
            LOG.error(
                    "Scopes have been requested which this client is not supported to request. Scopes in request: {}",
                    scopes);
            return false;
        }
        return true;
    }

    private boolean areClaimsValid(OIDCClaimsRequest claimsRequest, ClientRegistry clientRegistry) {
        if (claimsRequest == null) {
            LOG.info("No claims present in auth request");
            return true;
        }
        List<String> claimNames =
                claimsRequest.getUserInfoClaimsRequest().getEntries().stream()
                        .map(ClaimsSetRequest.Entry::getClaimName)
                        .collect(Collectors.toList());

        boolean containsUnsupportedClaims =
                claimNames.stream()
                        .anyMatch(
                                claim ->
                                        ValidClaims.getAllValidClaims().stream()
                                                .noneMatch(t -> t.equals(claim)));
        if (containsUnsupportedClaims) {
            LOG.error(
                    () ->
                            "Claims have been requested which are not yet supported. Claims in request: "
                                    + claimsRequest.toJSONString());
            return false;
        }

        boolean hasUnsupportedClaims = !clientRegistry.getClaims().containsAll(claimNames);
        if (hasUnsupportedClaims) {
            LOG.error(
                    () ->
                            "Claims have been requested which this client is not supported to request. Claims in request: {}"
                                    + claimsRequest.toJSONString());
            return false;
        }
        LOG.info("Claims are present AND valid in auth request");
        return true;
    }

    public String getExistingOrCreateNewPersistentSessionId(Map<String, String> headers) {
        return PersistentIdHelper.getExistingOrCreateNewPersistentSessionId(headers);
    }

    public boolean isTestJourney(ClientID clientID, String emailAddress) {
        var isTestJourney = dynamoClientService.isTestJourney(clientID.toString(), emailAddress);
        LOG.info("Is journey a test journey: {}", isTestJourney);
        return isTestJourney;
    }

    public void storeState(String sessionId, State state) {
        LOG.info("Storing state");
        redisConnectionService.saveWithExpiry(
                AUTHENTICATION_STATE_STORAGE_PREFIX + sessionId,
                state.getValue(),
                configurationService.getSessionExpiry());
    }

    public boolean jarRequiredForClient(AuthenticationRequest authRequest) {
        return authRequest.getScope().contains(CustomScopeValue.DOC_CHECKING_APP);
    }

    public Optional<AuthRequestError> validateJarParameters(AuthenticationRequest authRequest)
            throws ParseException {

        // TODO: all this is duplicated but can be extracted when logic in RequestObjectService is
        // moved to this class
        var clientId = authRequest.getClientID().toString();
        attachLogFieldToLogs(CLIENT_ID, clientId);
        var client = dynamoClientService.getClient(clientId).orElse(null);

        var signedJWT = (SignedJWT) authRequest.getRequestObject();
        var jwtClaimsSet = signedJWT.getJWTClaimsSet();

        if (jwtClaimsSet.getStringClaim("redirect_uri") == null
                || !client.getRedirectUrls()
                        .contains(jwtClaimsSet.getStringClaim("redirect_uri"))) {
            throw new RuntimeException("Invalid Redirect URI in request JWT");
        }

        var redirectURI = URI.create((String) jwtClaimsSet.getClaim("redirect_uri"));

        // ---------

        var params = authRequest.toParameters();
        if (params.size() != 4) {
            return errorResponse(redirectURI, OAuth2Error.INVALID_REQUEST);
        }

        if (!(params.containsKey("response_type")
                && params.containsKey("client_id")
                && params.containsKey("scope")
                && params.containsKey("request"))) {
            return errorResponse(redirectURI, OAuth2Error.INVALID_REQUEST);
        }

        // TODO: this should be moved to a "validateClient" method
        if (!ClientType.APP.getValue().equals(client.getClientType())
                && !ClientType.WEB.getValue().equals(client.getClientType())) {
            LOG.error("ClientType of client is not 'app' or 'web'");
            return errorResponse(redirectURI, OAuth2Error.UNAUTHORIZED_CLIENT);
        }

        if (!CODE.toString().equals(authRequest.getResponseType().toString())) {
            LOG.error(
                    "Unsupported responseType included in request. Expected responseType of code");
            return errorResponse(redirectURI, OAuth2Error.UNSUPPORTED_RESPONSE_TYPE);
        }

        if (requestContainsInvalidScopes(authRequest.getScope(), client)) {
            LOG.error(
                    "Invalid scopes in authRequest. Scopes in request: {}",
                    authRequest.getScope().toStringList());
            return errorResponse(redirectURI, OAuth2Error.INVALID_SCOPE);
        }

        return Optional.empty();
    }

    private static Optional<AuthRequestError> errorResponse(URI uri, ErrorObject error) {
        return Optional.of(new AuthRequestError(error, uri));
    }

    private boolean requestContainsInvalidScopes(Scope scopes, ClientRegistry clientRegistry) {
        for (String scope : scopes.toStringList()) {
            if (!ValidScopes.getAllValidScopes().contains(scope)) {
                return true;
            }
            if (!clientRegistry.getScopes().contains(scope)) {
                return true;
            }
        }
        return false;
    }
}
