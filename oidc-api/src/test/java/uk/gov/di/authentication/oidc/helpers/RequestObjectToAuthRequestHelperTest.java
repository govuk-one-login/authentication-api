package uk.gov.di.authentication.oidc.helpers;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.entity.CredentialTrustLevel;
import uk.gov.di.authentication.shared.entity.LevelOfConfidence;
import uk.gov.di.authentication.shared.entity.VectorOfTrust;
import uk.gov.di.authentication.sharedtest.helper.JsonArrayHelper;
import uk.gov.di.authentication.sharedtest.helper.KeyPairHelper;

import java.net.URI;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertNull;
import static uk.gov.di.authentication.oidc.helper.RequestObjectTestHelper.generateSignedJWT;

class RequestObjectToAuthRequestHelperTest {

    private static final ClientID CLIENT_ID = new ClientID("test-id");
    private static final String AUDIENCE = "https://localhost/authorize";
    private static final URI REDIRECT_URI = URI.create("https://localhost:8080");
    private static final State STATE = new State();
    private static final Nonce NONCE = new Nonce();

    @Test
    void shouldConvertRequestObjectToAuthRequest() throws JOSEException {
        var keyPair = KeyPairHelper.GENERATE_RSA_KEY_PAIR();
        var scope = new Scope(OIDCScopeValue.OPENID, OIDCScopeValue.EMAIL);
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .audience(AUDIENCE)
                        .claim("redirect_uri", REDIRECT_URI.toString())
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", scope.toString())
                        .claim("nonce", NONCE)
                        .claim("state", STATE)
                        .claim("client_id", CLIENT_ID.getValue())
                        .issuer(CLIENT_ID.getValue())
                        .build();
        var signedJWT = generateSignedJWT(jwtClaimsSet, keyPair);
        var authRequest =
                new AuthenticationRequest.Builder(
                                ResponseType.CODE,
                                new Scope(OIDCScopeValue.OPENID),
                                CLIENT_ID,
                                null)
                        .requestObject(signedJWT)
                        .build();

        var transformedAuthRequest = RequestObjectToAuthRequestHelper.transform(authRequest);

        assertThat(transformedAuthRequest.getState(), equalTo(STATE));
        assertThat(transformedAuthRequest.getNonce(), equalTo(NONCE));
        assertThat(transformedAuthRequest.getRedirectionURI(), equalTo(REDIRECT_URI));
        assertThat(transformedAuthRequest.getScope(), equalTo(scope));
        assertThat(transformedAuthRequest.getClientID(), equalTo(CLIENT_ID));
        assertThat(transformedAuthRequest.getResponseType(), equalTo(ResponseType.CODE));
        assertThat(transformedAuthRequest.getRequestObject(), equalTo(signedJWT));
    }

    @Test
    void shouldConvertRequestObjectToAuthRequestWhenVTRClaimIsPresent() throws JOSEException {
        var keyPair = KeyPairHelper.GENERATE_RSA_KEY_PAIR();
        var scope = new Scope(OIDCScopeValue.OPENID, OIDCScopeValue.EMAIL);
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .audience(AUDIENCE)
                        .claim("redirect_uri", REDIRECT_URI.toString())
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", scope.toString())
                        .claim("nonce", NONCE)
                        .claim("state", STATE)
                        .claim("client_id", CLIENT_ID.getValue())
                        .claim("vtr", JsonArrayHelper.jsonArrayOf("P2.Cl.Cm"))
                        .issuer(CLIENT_ID.getValue())
                        .build();
        var signedJWT = generateSignedJWT(jwtClaimsSet, keyPair);
        var authRequest =
                new AuthenticationRequest.Builder(
                                ResponseType.CODE,
                                new Scope(OIDCScopeValue.OPENID),
                                CLIENT_ID,
                                null)
                        .requestObject(signedJWT)
                        .build();

        var transformedAuthRequest = RequestObjectToAuthRequestHelper.transform(authRequest);

        var vtr =
                VectorOfTrust.parseFromAuthRequestAttribute(
                        transformedAuthRequest.getCustomParameter("vtr"));
        assertThat(vtr.getCredentialTrustLevel(), equalTo(CredentialTrustLevel.MEDIUM_LEVEL));
        assertThat(vtr.getLevelOfConfidence(), equalTo(LevelOfConfidence.MEDIUM_LEVEL));
        assertThat(transformedAuthRequest.getState(), equalTo(STATE));
        assertThat(transformedAuthRequest.getNonce(), equalTo(NONCE));
        assertThat(transformedAuthRequest.getRedirectionURI(), equalTo(REDIRECT_URI));
        assertThat(transformedAuthRequest.getScope(), equalTo(scope));
        assertThat(transformedAuthRequest.getClientID(), equalTo(CLIENT_ID));
        assertThat(transformedAuthRequest.getResponseType(), equalTo(ResponseType.CODE));
        assertThat(transformedAuthRequest.getRequestObject(), equalTo(signedJWT));
    }

    @Test
    void shouldReturnAuthRequestWhenNoRequestObjectIsPresent() {
        Scope scope = new Scope(OIDCScopeValue.OPENID, OIDCScopeValue.PHONE);
        var authRequest =
                new AuthenticationRequest.Builder(ResponseType.CODE, scope, CLIENT_ID, REDIRECT_URI)
                        .state(STATE)
                        .nonce(NONCE)
                        .build();

        var transformedAuthRequest = RequestObjectToAuthRequestHelper.transform(authRequest);

        assertNull(transformedAuthRequest.getRequestObject());
        assertThat(transformedAuthRequest.getState(), equalTo(authRequest.getState()));
        assertThat(transformedAuthRequest.getNonce(), equalTo(authRequest.getNonce()));
        assertThat(transformedAuthRequest.getClientID(), equalTo(authRequest.getClientID()));
        assertThat(
                transformedAuthRequest.getRedirectionURI(),
                equalTo(authRequest.getRedirectionURI()));
        assertThat(
                transformedAuthRequest.getResponseType(), equalTo(authRequest.getResponseType()));
        assertThat(transformedAuthRequest.getScope(), equalTo(authRequest.getScope()));
    }
}
