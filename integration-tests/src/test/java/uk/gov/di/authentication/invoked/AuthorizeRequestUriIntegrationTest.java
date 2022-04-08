package uk.gov.di.authentication.invoked;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.oidc.lambda.AuthorizeRequestUriHandler;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.RequestUriPayload;
import uk.gov.di.authentication.sharedtest.basetest.HandlerIntegrationTest;
import uk.gov.di.authentication.sharedtest.extensions.RequestURIStubExtension;
import uk.gov.di.authentication.sharedtest.helper.KeyPairHelper;

import java.net.URI;
import java.security.KeyPair;
import java.util.Base64;

import static java.lang.String.format;
import static java.util.Collections.singletonList;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AuthorizeRequestUriIntegrationTest extends HandlerIntegrationTest {

    private static final String REDIRECT_URI = "https://localhost:8080";
    private static final State STATE = new State();
    private static final ClientID CLIENT_ID = new ClientID("test-id");
    private KeyPair keyPair;

    @RegisterExtension
    public static final RequestURIStubExtension requestURIStub = new RequestURIStubExtension();

    private final AuthorizeRequestUriHandler handler =
            new AuthorizeRequestUriHandler(TEST_CONFIGURATION_SERVICE);

    @Test
    void shouldReturn200WithValidIPVAuthorisationRequest() throws JOSEException {
        keyPair = KeyPairHelper.GENERATE_RSA_KEY_PAIR();
        requestURIStub.init(createSignedJWT(keyPair));
        var requestURI =
                URI.create(
                        format(
                                "http://localhost:%s/stub-request-uri",
                                requestURIStub.getHttpPort()));
        var response =
                handler.handleRequest(
                        new RequestUriPayload(
                                generateClientRegistry(requestURI, keyPair),
                                generateAuthRequest(requestURI)),
                        context);

        assertTrue(response.isSuccessfulRequest());
    }

    private SignedJWT createSignedJWT(KeyPair keyPair) throws JOSEException {
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .audience("http://localhost")
                        .claim("redirect_uri", REDIRECT_URI)
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", new Scope(OIDCScopeValue.OPENID).toString())
                        .claim("client_id", CLIENT_ID.getValue())
                        .issuer(CLIENT_ID.getValue())
                        .build();
        var jwsHeader = new JWSHeader(JWSAlgorithm.RS256);
        var signedJWT = new SignedJWT(jwsHeader, jwtClaimsSet);
        var signer = new RSASSASigner(keyPair.getPrivate());
        signedJWT.sign(signer);
        return signedJWT;
    }

    private ClientRegistry generateClientRegistry(URI requestURI, KeyPair keyPair) {
        return new ClientRegistry()
                .setClientID(CLIENT_ID.getValue())
                .setConsentRequired(false)
                .setClientName("test-client")
                .setScopes(singletonList("openid"))
                .setRedirectUrls(singletonList(REDIRECT_URI))
                .setRequestUris(singletonList(requestURI.toString()))
                .setSectorIdentifierUri("https://test.com")
                .setPublicKey(
                        Base64.getMimeEncoder().encodeToString(keyPair.getPublic().getEncoded()))
                .setSubjectType("pairwise");
    }

    private AuthenticationRequest generateAuthRequest(URI requestUri) {
        Scope scope = new Scope();
        scope.add(OIDCScopeValue.OPENID);
        AuthenticationRequest.Builder builder =
                new AuthenticationRequest.Builder(
                                ResponseType.CODE, scope, CLIENT_ID, URI.create(REDIRECT_URI))
                        .state(STATE)
                        .nonce(new Nonce())
                        .requestURI(requestUri);
        return builder.build();
    }
}
