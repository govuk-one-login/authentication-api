package uk.gov.di.authentication.oidc.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.RequestUriPayload;
import uk.gov.di.authentication.shared.entity.RequestUriResponsePayload;
import uk.gov.di.authentication.shared.entity.ValidScopes;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.util.Base64;
import java.util.List;
import java.util.Objects;

public class AuthorizeRequestUriHandler
        implements RequestHandler<RequestUriPayload, RequestUriResponsePayload> {

    private final HttpClient httpClient;
    private final ConfigurationService configurationService;
    private static final Logger LOG = LogManager.getLogger(AuthorizeRequestUriHandler.class);

    public AuthorizeRequestUriHandler(
            HttpClient httpClient, ConfigurationService configurationService) {
        this.httpClient = httpClient;
        this.configurationService = configurationService;
    }

    public AuthorizeRequestUriHandler(ConfigurationService configurationService) {
        httpClient = HttpClient.newBuilder().version(HttpClient.Version.HTTP_2).build();
        this.configurationService = configurationService;
    }

    public AuthorizeRequestUriHandler() {
        this(ConfigurationService.getInstance());
    }

    @Override
    public RequestUriResponsePayload handleRequest(RequestUriPayload input, Context context) {
        try {
            LOG.info("Request received to the AuthorizeRequestUriHandler");
            var client = input.getClientRegistry();
            var signedJWTResponse = getSignedJWTResponse(input.getAuthRequest().getRequestURI());
            if (signedJWTResponse.statusCode() < 200 && signedJWTResponse.statusCode() >= 300) {
                LOG.error(
                        "Unsuccessful response when requesting `request_uri`. Status code was: {}",
                        signedJWTResponse.statusCode());
                throw new RuntimeException();
            }
            var signedJWT = SignedJWT.parse(signedJWTResponse.body());
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
            if (Objects.isNull(jwtClaimsSet.getClaim("client_id"))
                    || !jwtClaimsSet
                            .getClaim("client_id")
                            .toString()
                            .equals(input.getAuthRequest().getClientID().getValue())) {
                return new RequestUriResponsePayload(
                        false, OAuth2Error.UNAUTHORIZED_CLIENT.toParameters());
            }
            if (Objects.nonNull(jwtClaimsSet.getClaim("request"))
                    || Objects.nonNull(jwtClaimsSet.getClaim("request_uri"))) {
                LOG.warn("request or request_uri claim should not be incldued in request JWT");
                return new RequestUriResponsePayload(
                        false, OAuth2Error.INVALID_REQUEST.toParameters());
            }
            if (Objects.isNull(jwtClaimsSet.getAudience())
                    || !jwtClaimsSet
                            .getAudience()
                            .contains(configurationService.getOidcApiBaseURL().orElseThrow())) {
                LOG.warn("Invalid or missing audience");
                return new RequestUriResponsePayload(
                        false, OAuth2Error.ACCESS_DENIED.toParameters());
            }
            if (Objects.isNull(jwtClaimsSet.getIssuer())
                    || !jwtClaimsSet.getIssuer().equals(client.getClientID())) {
                LOG.warn("Invalid or missing issuer");
                return new RequestUriResponsePayload(
                        false, OAuth2Error.UNAUTHORIZED_CLIENT.toParameters());
            }
            if (!ResponseType.CODE.toString().equals(jwtClaimsSet.getClaim("response_type"))) {
                LOG.warn(
                        "Unsupported responseType included in request JWT. Expected responseType of code");
                return new RequestUriResponsePayload(
                        false, OAuth2Error.UNSUPPORTED_RESPONSE_TYPE.toParameters());
            }
            if (Objects.isNull(jwtClaimsSet.getClaim("scope"))
                    || !areScopesValid(
                            Scope.parse(jwtClaimsSet.getClaim("scope").toString()).toStringList(),
                            client)) {
                LOG.warn("Invalid scopes in request JWT");
                return new RequestUriResponsePayload(
                        false, OAuth2Error.INVALID_SCOPE.toParameters());
            }
        } catch (InterruptedException | IOException e) {
            LOG.error("Error when retrieving request JWT", e);
            throw new RuntimeException(e);
        } catch (ParseException e) {
            LOG.error("Error when parsing request JWT", e);
            throw new RuntimeException(e);
        }
        LOG.info("Generating RequestUriResponsePayload response");
        return new RequestUriResponsePayload(true);
    }

    private HttpResponse<String> getSignedJWTResponse(URI requestUri)
            throws IOException, InterruptedException {
        var request = HttpRequest.newBuilder().GET().uri(requestUri).build();
        return httpClient.send(request, HttpResponse.BodyHandlers.ofString());
    }

    public static boolean isSignatureValid(SignedJWT signedJWT, String publicKey) {
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

    private boolean areScopesValid(List<String> scopes, ClientRegistry clientRegistry) {
        for (String scope : scopes) {
            if (ValidScopes.getAllValidScopes().stream().noneMatch(t -> t.equals(scope))) {
                return false;
            }
        }
        return clientRegistry.getScopes().containsAll(scopes);
    }
}
