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
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import uk.gov.di.authentication.oidc.entity.AuthRequestError;
import uk.gov.di.authentication.oidc.services.IPVCapacityService;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.ClientType;
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
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import static com.nimbusds.oauth2.sdk.ResponseType.CODE;
import static java.util.Collections.emptyList;
import static uk.gov.di.authentication.shared.helpers.ConstructUriHelper.buildURI;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.LogFieldName.CLIENT_ID;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachLogFieldToLogs;

public class RequestObjectAuthorizeValidator extends BaseAuthorizeValidator {

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

            if (Arrays.stream(ClientType.values())
                    .noneMatch(type -> type.getValue().equals(client.getClientType()))) {
                LOG.error("ClientType value of {} is not recognised", client.getClientType());
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
            if (Objects.isNull(jwtClaimsSet.getClaim("client_id"))
                    || !jwtClaimsSet
                            .getClaim("client_id")
                            .toString()
                            .equals(authRequest.getClientID().getValue())) {
                return errorResponse(redirectURI, OAuth2Error.UNAUTHORIZED_CLIENT);
            }
            if (Objects.nonNull(jwtClaimsSet.getClaim("request"))
                    || Objects.nonNull(jwtClaimsSet.getClaim("request_uri"))) {
                LOG.error("request or request_uri claim should not be included in request JWT");
                return errorResponse(redirectURI, OAuth2Error.INVALID_REQUEST);
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
                LOG.error("Invalid or missing audience");
                return errorResponse(redirectURI, OAuth2Error.ACCESS_DENIED);
            }
            if (Objects.isNull(jwtClaimsSet.getIssuer())
                    || !jwtClaimsSet.getIssuer().equals(client.getClientID())) {
                LOG.error("Invalid or missing issuer");
                return errorResponse(redirectURI, OAuth2Error.UNAUTHORIZED_CLIENT);
            }

            if (!CODE.toString().equals(jwtClaimsSet.getClaim("response_type"))) {
                LOG.error(
                        "Unsupported responseType included in request JWT. Expected responseType of code");
                return errorResponse(redirectURI, OAuth2Error.UNSUPPORTED_RESPONSE_TYPE);
            }
            if (Objects.isNull(jwtClaimsSet.getClaim("scope"))
                    || requestContainsInvalidScopes(
                            Scope.parse(jwtClaimsSet.getClaim("scope").toString()), client)) {
                LOG.error("Invalid scopes in request JWT");
                return errorResponse(redirectURI, OAuth2Error.INVALID_SCOPE);
            }
            if (Objects.isNull(jwtClaimsSet.getClaim("state"))) {
                LOG.error("State is missing from authRequest");
                return errorResponse(
                        redirectURI,
                        new ErrorObject(
                                OAuth2Error.INVALID_REQUEST_CODE,
                                "Request is missing state parameter"));
            }
            if (Objects.isNull(jwtClaimsSet.getClaim("nonce"))) {
                LOG.error("Nonce is missing from authRequest");
                return errorResponse(
                        redirectURI,
                        new ErrorObject(
                                OAuth2Error.INVALID_REQUEST_CODE,
                                "Request is missing nonce parameter"));
            }
            var vtrError = validateVtr(jwtClaimsSet, redirectURI);
            if (vtrError.isPresent()) {
                return vtrError;
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
                                    "ui_locales parameter is invalid"));
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
                return errorResponse(redirectURI, OAuth2Error.TEMPORARILY_UNAVAILABLE);
            }
        } catch (IllegalArgumentException e) {
            LOG.error(
                    "vtr in AuthRequest is not valid. vtr in request: {}. IllegalArgumentException: {}",
                    authRequestVtr,
                    e);
            return errorResponse(
                    redirectURI,
                    new ErrorObject(OAuth2Error.INVALID_REQUEST_CODE, "Request vtr not valid"));
        }
        return Optional.empty();
    }

    private static Optional<AuthRequestError> errorResponse(URI uri, ErrorObject error) {
        return Optional.of(new AuthRequestError(error, uri));
    }
}
