package uk.gov.di.authentication.oidc.validators;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.langtag.LangTagException;
import com.nimbusds.langtag.LangTagUtils;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import uk.gov.di.authentication.oidc.entity.AuthRequestError;
import uk.gov.di.authentication.oidc.services.IPVCapacityService;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.entity.ClientType;
import uk.gov.di.orchestration.shared.entity.ValidScopes;
import uk.gov.di.orchestration.shared.entity.VectorOfTrust;
import uk.gov.di.orchestration.shared.serialization.Json;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.DynamoClientService;
import uk.gov.di.orchestration.shared.services.SerializationService;

import java.net.URI;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import static com.nimbusds.oauth2.sdk.ResponseType.CODE;
import static java.util.Collections.emptyList;
import static uk.gov.di.orchestration.shared.helpers.ConstructUriHelper.buildURI;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.CLIENT_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.attachLogFieldToLogs;

public class RequestObjectAuthorizeValidator extends BaseAuthorizeValidator {
    private static final Json objectMapper = SerializationService.getInstance();

    public RequestObjectAuthorizeValidator(
            DynamoClientService dynamoClientService,
            ConfigurationService configurationService,
            IPVCapacityService ipvCapacityService) {
        super(configurationService, dynamoClientService, ipvCapacityService);
    }

    public RequestObjectAuthorizeValidator(ConfigurationService configurationService) {
        super(
                configurationService,
                new DynamoClientService(configurationService),
                new IPVCapacityService(configurationService));
    }

    @Override
    public Optional<AuthRequestError> validate(AuthenticationRequest authRequest) {

        var clientId = authRequest.getClientID().toString();
        attachLogFieldToLogs(CLIENT_ID, clientId);
        ClientRegistry client = getClientFromDynamo(clientId);

        var signedJWT = (SignedJWT) authRequest.getRequestObject();
        var signatureValid = isSignatureValid(signedJWT, client.getPublicKey());
        if (!signatureValid) {
            LOG.error("Invalid Signature on request JWT");
            throw new RuntimeException();
        }

        try {
            var jwtClaimsSet = signedJWT.getJWTClaimsSet();

            if (jwtClaimsSet.getStringClaim("redirect_uri") == null
                    || !client.getRedirectUrls()
                            .contains(jwtClaimsSet.getStringClaim("redirect_uri"))) {
                throw new RuntimeException("Invalid Redirect URI in request JWT");
            }

            var redirectURI = URI.create((String) jwtClaimsSet.getClaim("redirect_uri"));

            if (Objects.isNull(jwtClaimsSet.getClaim("state"))) {
                LOG.error("State is missing from authRequest");
                return errorResponse(
                        redirectURI,
                        new ErrorObject(
                                OAuth2Error.INVALID_REQUEST_CODE,
                                "Request is missing state parameter"),
                        null);
            }

            State state = new State(jwtClaimsSet.getStringClaim("state"));

            if (Arrays.stream(ClientType.values())
                    .noneMatch(type -> type.getValue().equals(client.getClientType()))) {
                LOG.error("ClientType value of {} is not recognised", client.getClientType());
                return errorResponse(redirectURI, OAuth2Error.UNAUTHORIZED_CLIENT, state);
            }

            if (!CODE.toString().equals(authRequest.getResponseType().toString())) {
                LOG.error(
                        "Unsupported responseType included in request. Expected responseType of code");
                return errorResponse(redirectURI, OAuth2Error.UNSUPPORTED_RESPONSE_TYPE, state);
            }

            if (requestContainsInvalidScopes(authRequest.getScope(), client)) {
                LOG.error(
                        "Invalid scopes in authRequest. Scopes in request: {}",
                        authRequest.getScope().toStringList());
                return errorResponse(redirectURI, OAuth2Error.INVALID_SCOPE, state);
            }
            if (Objects.isNull(jwtClaimsSet.getClaim("client_id"))
                    || !jwtClaimsSet
                            .getClaim("client_id")
                            .toString()
                            .equals(authRequest.getClientID().getValue())) {
                return errorResponse(redirectURI, OAuth2Error.UNAUTHORIZED_CLIENT, state);
            }
            if (Objects.nonNull(jwtClaimsSet.getClaim("request"))
                    || Objects.nonNull(jwtClaimsSet.getClaim("request_uri"))) {
                LOG.error("request or request_uri claim should not be included in request JWT");
                return errorResponse(redirectURI, OAuth2Error.INVALID_REQUEST, state);
            }
            if (Objects.isNull(jwtClaimsSet.getAudience())
                    || !jwtClaimsSet
                            .getAudience()
                            .contains(
                                    buildURI(
                                                    configurationService
                                                            .getOidcApiBaseURL()
                                                            .map(URI::toString)
                                                            .orElseThrow(),
                                                    "/authorize")
                                            .toString())) {
                LOG.error("Invalid or missing audience");
                return errorResponse(redirectURI, OAuth2Error.ACCESS_DENIED, state);
            }
            if (Objects.isNull(jwtClaimsSet.getIssuer())
                    || !jwtClaimsSet.getIssuer().equals(client.getClientID())) {
                LOG.error("Invalid or missing issuer");
                return errorResponse(redirectURI, OAuth2Error.UNAUTHORIZED_CLIENT, state);
            }

            if (!CODE.toString().equals(jwtClaimsSet.getClaim("response_type"))) {
                LOG.error(
                        "Unsupported responseType included in request JWT. Expected responseType of code");
                return errorResponse(redirectURI, OAuth2Error.UNSUPPORTED_RESPONSE_TYPE, state);
            }
            if (Objects.isNull(jwtClaimsSet.getClaim("scope"))
                    || requestContainsInvalidScopes(
                            Scope.parse(jwtClaimsSet.getClaim("scope").toString()), client)) {
                LOG.error("Invalid scopes in request JWT");
                return errorResponse(redirectURI, OAuth2Error.INVALID_SCOPE, state);
            }
            if (Objects.isNull(jwtClaimsSet.getClaim("nonce"))) {
                LOG.error("Nonce is missing from authRequest");
                return errorResponse(
                        redirectURI,
                        new ErrorObject(
                                OAuth2Error.INVALID_REQUEST_CODE,
                                "Request is missing nonce parameter"),
                        state);
            }
            var vtrError = validateVtr(jwtClaimsSet, client);
            if (vtrError.isPresent()) {
                return errorResponse(redirectURI, vtrError.get(), state);
            }
            if (Objects.nonNull(jwtClaimsSet.getClaim("ui_locales"))) {
                try {
                    String uiLocales = (String) jwtClaimsSet.getClaim("ui_locales");
                    LangTagUtils.parseLangTagList(uiLocales.split(" "));
                } catch (ClassCastException | LangTagException e) {
                    LOG.warn("ui_locales parameter is invalid: {}", e.getMessage());
                    return errorResponse(
                            redirectURI,
                            new ErrorObject(
                                    OAuth2Error.INVALID_REQUEST_CODE,
                                    "ui_locales parameter is invalid"),
                            state);
                }
            }
            LOG.info("RequestObject has passed initial validation");
            return Optional.empty();
        } catch (ParseException e) {
            throw new RuntimeException(e);
        }
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

    private static boolean isSignatureValid(SignedJWT signedJWT, String publicKey) {
        try {
            byte[] decodedKey = Base64.getMimeDecoder().decode(publicKey);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decodedKey);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PublicKey pubKey = kf.generatePublic(keySpec);
            JWSVerifier verifier = new RSASSAVerifier((RSAPublicKey) pubKey);
            return signedJWT.verify(verifier);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | JOSEException e) {
            LOG.error("Error when validating JWT signature");
            throw new RuntimeException(e);
        }
    }

    private Optional<ErrorObject> validateVtr(JWTClaimsSet jwtClaimsSet, ClientRegistry client) {
        List<String> authRequestVtr = new ArrayList<>();
        try {
            authRequestVtr = getRequestObjectVtrAsList(jwtClaimsSet);
            var vtrList = VectorOfTrust.parseFromAuthRequestAttribute(authRequestVtr);
            var levelOfConfidenceValues = VectorOfTrust.getRequestedLevelsOfConfidence(vtrList);
            if (!client.getClientLoCs().containsAll(levelOfConfidenceValues)) {
                LOG.error(
                        "Level of confidence values have been requested which this client is not permitted to request. Level of confidence values in request: {}",
                        levelOfConfidenceValues);
                return Optional.of(
                        new ErrorObject(
                                OAuth2Error.INVALID_REQUEST_CODE, "Request vtr is not permitted"));
            }
            if (vtrList.get(0).containsLevelOfConfidence()
                    && !ipvCapacityService.isIPVCapacityAvailable()) {
                return Optional.of(OAuth2Error.TEMPORARILY_UNAVAILABLE);
            }
        } catch (IllegalArgumentException e) {
            LOG.error(
                    "vtr in AuthRequest is not valid. vtr in request: {}. IllegalArgumentException: {}",
                    authRequestVtr,
                    e);
            return Optional.of(
                    new ErrorObject(OAuth2Error.INVALID_REQUEST_CODE, "Request vtr not valid"));
        } catch (ParseException | Json.JsonException e) {
            LOG.error("Parse exception thrown when validating vtr", e);
            return Optional.of(
                    new ErrorObject(OAuth2Error.INVALID_REQUEST_CODE, "Request vtr not valid"));
        }
        return Optional.empty();
    }

    private List<String> getRequestObjectVtrAsList(JWTClaimsSet jwtClaimsSet)
            throws ParseException, Json.JsonException {
        var vtrClaim = jwtClaimsSet.getClaim("vtr");
        if (vtrClaim == null) {
            return emptyList();
        } else if (vtrClaim instanceof String vtr) {
            return List.of(vtr);
        } else if (vtrClaim instanceof List<?> vtrList
                && vtrList.stream().allMatch(String.class::isInstance)) {
            return List.of(
                    objectMapper.writeValueAsString(jwtClaimsSet.getStringArrayClaim("vtr")));
        }

        throw new ParseException("vtr is in an invalid format. Could not be parsed.", 0);
    }

    private static Optional<AuthRequestError> errorResponse(
            URI uri, ErrorObject error, State state) {
        return Optional.of(new AuthRequestError(error, uri, state));
    }
}
