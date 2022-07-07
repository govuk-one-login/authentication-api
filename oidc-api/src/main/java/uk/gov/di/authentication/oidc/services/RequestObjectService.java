package uk.gov.di.authentication.oidc.services;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.oidc.entity.AuthRequestError;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.ClientType;
import uk.gov.di.authentication.shared.entity.CustomScopeValue;
import uk.gov.di.authentication.shared.entity.ValidScopes;
import uk.gov.di.authentication.shared.entity.VectorOfTrust;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoClientService;

import java.net.URI;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import static java.util.Collections.emptyList;
import static uk.gov.di.authentication.shared.helpers.ConstructUriHelper.buildURI;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.LogFieldName.CLIENT_ID;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachLogFieldToLogs;

public class RequestObjectService {

    private static final Logger LOG = LogManager.getLogger(RequestObjectService.class);

    public static final String VTR_PARAM = "vtr";
    private final DynamoClientService dynamoClientService;
    private final ConfigurationService configurationService;
    private final IPVCapacityService ipvCapacityService;

    public RequestObjectService(
            DynamoClientService dynamoClientService,
            ConfigurationService configurationService,
            IPVCapacityService ipvCapacityService) {
        this.dynamoClientService = dynamoClientService;
        this.configurationService = configurationService;
        this.ipvCapacityService = ipvCapacityService;
    }

    public RequestObjectService(ConfigurationService configurationService) {
        this(
                new DynamoClientService(configurationService),
                configurationService,
                new IPVCapacityService(configurationService));
    }

    public Optional<AuthRequestError> validateRequestObject(AuthenticationRequest authRequest) {
        var clientId = authRequest.getClientID().toString();

        attachLogFieldToLogs(CLIENT_ID, clientId);

        var client = dynamoClientService.getClient(clientId).orElse(null);
        try {

            if (Objects.isNull(client)) {
                var errorMsg = "No Client found with given ClientID";
                LOG.warn(errorMsg);
                throw new RuntimeException(errorMsg);
            }
            var signedJWT = (SignedJWT) authRequest.getRequestObject();
            var signatureValid = isSignatureValid(signedJWT, client.getPublicKey());
            if (!signatureValid) {
                LOG.error("Invalid Signature on request JWT");
                throw new RuntimeException();
            }
            var jwtClaimsSet = signedJWT.getJWTClaimsSet();
            if (client.getRedirectUrls().stream()
                    .filter(Objects::nonNull)
                    .noneMatch(s -> s.equals(jwtClaimsSet.getClaim("redirect_uri")))) {
                throw new RuntimeException("Invalid Redirect URI in request JWT");
            }
            var redirectURI = URI.create((String) jwtClaimsSet.getClaim("redirect_uri"));
            if (Boolean.FALSE.equals(client.getClientType().equals(ClientType.APP.getValue()))) {
                LOG.warn("ClientType of client is not 'app'");
                return Optional.of(
                        new AuthRequestError(OAuth2Error.UNAUTHORIZED_CLIENT, redirectURI));
            }
            if (!authRequest.getResponseType().toString().equals(ResponseType.CODE.toString())) {
                LOG.warn(
                        "Unsupported responseType included in request. Expected responseType of code");
                return Optional.of(
                        new AuthRequestError(OAuth2Error.UNSUPPORTED_RESPONSE_TYPE, redirectURI));
            }
            if (requestContainsInvalidScopes(
                    authRequest.getScope().toStringList(), client, false)) {
                LOG.warn(
                        "Invalid scopes in authRequest. Scopes in request: {}",
                        authRequest.getScope().toStringList());
                return Optional.of(new AuthRequestError(OAuth2Error.INVALID_SCOPE, redirectURI));
            }
            if (Objects.isNull(jwtClaimsSet.getClaim("client_id"))
                    || !jwtClaimsSet
                            .getClaim("client_id")
                            .toString()
                            .equals(authRequest.getClientID().getValue())) {
                return Optional.of(
                        new AuthRequestError(OAuth2Error.UNAUTHORIZED_CLIENT, redirectURI));
            }
            if (Objects.nonNull(jwtClaimsSet.getClaim("request"))
                    || Objects.nonNull(jwtClaimsSet.getClaim("request_uri"))) {
                LOG.warn("request or request_uri claim should not be incldued in request JWT");
                return Optional.of(new AuthRequestError(OAuth2Error.INVALID_REQUEST, redirectURI));
            }
            if (Objects.isNull(jwtClaimsSet.getAudience())
                    || !jwtClaimsSet
                            .getAudience()
                            .contains(
                                    buildURI(
                                                    configurationService
                                                            .getOidcApiBaseURL()
                                                            .orElseThrow(),
                                                    "/authorize")
                                            .toString())) {
                LOG.warn("Invalid or missing audience");
                return Optional.of(new AuthRequestError(OAuth2Error.ACCESS_DENIED, redirectURI));
            }
            if (Objects.isNull(jwtClaimsSet.getIssuer())
                    || !jwtClaimsSet.getIssuer().equals(client.getClientID())) {
                LOG.warn("Invalid or missing issuer");
                return Optional.of(
                        new AuthRequestError(OAuth2Error.UNAUTHORIZED_CLIENT, redirectURI));
            }
            if (!ResponseType.CODE.toString().equals(jwtClaimsSet.getClaim("response_type"))) {
                LOG.warn(
                        "Unsupported responseType included in request JWT. Expected responseType of code");
                return Optional.of(
                        new AuthRequestError(OAuth2Error.UNSUPPORTED_RESPONSE_TYPE, redirectURI));
            }
            if (Objects.isNull(jwtClaimsSet.getClaim("scope"))
                    || requestContainsInvalidScopes(
                            Scope.parse(jwtClaimsSet.getClaim("scope").toString()).toStringList(),
                            client,
                            true)) {
                LOG.warn("Invalid scopes in request JWT");
                return Optional.of(new AuthRequestError(OAuth2Error.INVALID_SCOPE, redirectURI));
            }
            if (Objects.isNull(jwtClaimsSet.getClaim("state"))) {
                LOG.warn("State is missing from authRequest");
                return Optional.of(
                        new AuthRequestError(
                                new ErrorObject(
                                        OAuth2Error.INVALID_REQUEST_CODE,
                                        "Request is missing state parameter"),
                                redirectURI));
            }
            if (Objects.isNull(jwtClaimsSet.getClaim("nonce"))) {
                LOG.warn("Nomce is missing from authRequest");
                return Optional.of(
                        new AuthRequestError(
                                new ErrorObject(
                                        OAuth2Error.INVALID_REQUEST_CODE,
                                        "Request is missing nonce parameter"),
                                redirectURI));
            }
            var vtrError = validateVtr(jwtClaimsSet, redirectURI);
            if (vtrError.isPresent()) {
                return vtrError;
            }
            LOG.info("RequestObject has passed initial validation");
            return Optional.empty();
        } catch (ParseException e) {
            throw new RuntimeException(e);
        }
    }

    private boolean requestContainsInvalidScopes(
            List<String> scopes, ClientRegistry clientRegistry, boolean requestObject) {
        if (requestObject && !scopes.contains(CustomScopeValue.DOC_CHECKING_APP.getValue())) {
            return true;
        }
        for (String scope : scopes) {
            if (ValidScopes.getAllValidScopes().stream().noneMatch(t -> t.equals(scope))) {
                return true;
            }
        }
        return !clientRegistry.getScopes().containsAll(scopes);
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

    private Optional<AuthRequestError> validateVtr(JWTClaimsSet jwtClaimsSet, URI redirectURI) {
        List<String> authRequestVtr = new ArrayList<>();
        try {
            authRequestVtr =
                    Objects.isNull(jwtClaimsSet.getClaim(VTR_PARAM))
                            ? emptyList()
                            : List.of(jwtClaimsSet.getClaim(VTR_PARAM).toString());
            var vectorOfTrust = VectorOfTrust.parseFromAuthRequestAttribute(authRequestVtr);
            if (vectorOfTrust.containsLevelOfConfidence()
                    && !ipvCapacityService.isIPVCapacityAvailable()) {
                return Optional.of(
                        new AuthRequestError(OAuth2Error.TEMPORARILY_UNAVAILABLE, redirectURI));
            }
        } catch (IllegalArgumentException e) {
            LOG.warn(
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
}
