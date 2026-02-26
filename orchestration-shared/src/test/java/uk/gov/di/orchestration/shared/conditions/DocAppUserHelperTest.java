package uk.gov.di.orchestration.shared.conditions;

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
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.entity.ClientType;
import uk.gov.di.orchestration.shared.entity.CustomScopeValue;
import uk.gov.di.orchestration.shared.entity.OrchClientSessionItem;
import uk.gov.di.orchestration.shared.entity.VectorOfTrust;
import uk.gov.di.orchestration.shared.state.UserContext;

import java.net.URI;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.orchestration.sharedtest.utils.KeyPairUtils.generateRsaKeyPair;

// QualityGateUnitTest
class DocAppUserHelperTest {

    private static final ClientID CLIENT_ID = new ClientID("client-id");
    private static final String CLIENT_NAME = "test-client";
    private static final String SESSION_ID = "a-session-id";
    private static final String AUDIENCE = "oidc-audience";
    private static final Scope VALID_SCOPE =
            new Scope(OIDCScopeValue.OPENID, CustomScopeValue.DOC_CHECKING_APP);
    private static final State STATE = new State();
    private static final Nonce NONCE = new Nonce();
    private static final String REDIRECT_URI = "https://localhost:8080";
    private static final Subject SUBJECT = new Subject();

    private static Stream<ClientType> clientTypes() {
        return Stream.of(ClientType.WEB, ClientType.APP);
    }

    // QualityGateRegressionTest
    @ParameterizedTest
    @MethodSource("clientTypes")
    void shouldReturnFalseIfAuthRequestDoesNotContainRequestObject(ClientType clientType) {
        var authRequest = getAuthRequest(null);
        var userContext = buildUserContext(clientType, authRequest, Optional.empty());

        Assertions.assertFalse(DocAppUserHelper.isDocCheckingAppUser(userContext));
    }

    // QualityGateRegressionTest
    @ParameterizedTest
    @MethodSource("clientTypes")
    void shouldReturnFalseIfRequestObjectDoesNotContainDocAppScope(ClientType clientType)
            throws JOSEException {
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .audience(AUDIENCE)
                        .claim("redirect_uri", REDIRECT_URI)
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", "openid")
                        .claim("client_id", CLIENT_ID.getValue())
                        .claim("state", STATE)
                        .issuer(CLIENT_ID.getValue())
                        .build();
        var signedJWT = generateSignedJWT(jwtClaimsSet);
        var authRequest =
                new AuthenticationRequest.Builder(
                                new ResponseType(ResponseType.Value.CODE),
                                new Scope(OIDCScopeValue.OPENID),
                                CLIENT_ID,
                                URI.create(REDIRECT_URI))
                        .nonce(NONCE)
                        .state(STATE)
                        .requestObject(signedJWT)
                        .build();
        var userContext = buildUserContext(clientType, authRequest, Optional.empty());

        assertFalse(DocAppUserHelper.isDocCheckingAppUser(userContext));
    }

    // QualityGateRegressionTest
    @Test
    void shouldReturnFalseIfClientIsNotAppClient() throws JOSEException {
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .audience(AUDIENCE)
                        .claim("redirect_uri", REDIRECT_URI)
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", VALID_SCOPE.toString())
                        .claim("client_id", CLIENT_ID.getValue())
                        .claim("state", STATE)
                        .issuer(CLIENT_ID.getValue())
                        .build();
        var signedJWT = generateSignedJWT(jwtClaimsSet);
        var authRequest = getAuthRequest(signedJWT);
        var userContext = buildUserContext(ClientType.WEB, authRequest, Optional.empty());

        assertFalse(DocAppUserHelper.isDocCheckingAppUser(userContext));
    }

    // QualityGateRegressionTest
    @Test
    void shouldReturnTrueIfClientIsDocCheckingAppUser() throws JOSEException {
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .audience(AUDIENCE)
                        .claim("redirect_uri", REDIRECT_URI)
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", VALID_SCOPE.toString())
                        .claim("client_id", CLIENT_ID.getValue())
                        .claim("state", STATE)
                        .issuer(CLIENT_ID.getValue())
                        .build();
        var signedJWT = generateSignedJWT(jwtClaimsSet);
        var authRequest = getAuthRequest(signedJWT);
        var userContext = buildUserContext(ClientType.APP, authRequest, Optional.empty());

        assertTrue(DocAppUserHelper.isDocCheckingAppUser(userContext));
    }

    // QualityGateRegressionTest
    @Test
    void shouldReturnTrueIfClientIsDocCheckingAppUserWithSubject() throws JOSEException {

        JWTClaimsSet.Builder claimsSetBuilder = getBaseJWTClaimsSetBuilder();

        var signedJWT = generateSignedJWT(claimsSetBuilder.build());
        var authRequest = getAuthRequest(signedJWT);
        var userContext = buildUserContext(ClientType.APP, authRequest, Optional.of(SUBJECT));

        assertTrue(
                DocAppUserHelper.isDocCheckingAppUserWithSubjectId(
                        userContext.getOrchClientSession()));
    }

    // QualityGateRegressionTest
    @Test
    void shouldReturnFalsIfClientIsDocCheckingAppUserWithoutSubject() throws JOSEException {

        JWTClaimsSet.Builder claimsSetBuilder = getBaseJWTClaimsSetBuilder();

        var signedJWT = generateSignedJWT(claimsSetBuilder.build());
        var authRequest = getAuthRequest(signedJWT);
        var userContext = buildUserContext(ClientType.APP, authRequest, Optional.empty());

        assertFalse(
                DocAppUserHelper.isDocCheckingAppUserWithSubjectId(
                        userContext.getOrchClientSession()));
    }

    private JWTClaimsSet.Builder getBaseJWTClaimsSetBuilder() {
        return new JWTClaimsSet.Builder()
                .audience(AUDIENCE)
                .claim("redirect_uri", REDIRECT_URI)
                .claim("response_type", ResponseType.CODE.toString())
                .claim("scope", VALID_SCOPE.toString())
                .claim("client_id", CLIENT_ID.getValue())
                .claim("state", STATE.getValue())
                .issuer(CLIENT_ID.getValue());
    }

    private UserContext buildUserContext(
            ClientType clientType, AuthenticationRequest authRequest, Optional<Subject> subject) {
        var orchClientSession =
                new OrchClientSessionItem(
                        "test-client-session-id",
                        authRequest.toParameters(),
                        LocalDateTime.now(),
                        List.of(VectorOfTrust.getDefaults()),
                        CLIENT_NAME);
        subject.map(Subject::getValue).ifPresent(orchClientSession::setDocAppSubjectId);
        var clientRegistry =
                new ClientRegistry()
                        .withClientID(CLIENT_ID.getValue())
                        .withClientName(CLIENT_NAME)
                        .withCookieConsentShared(false)
                        .withClientType(clientType.getValue());
        return UserContext.builder()
                .withSessionId(SESSION_ID)
                .withOrchClientSession(orchClientSession)
                .withClient(clientRegistry)
                .build();
    }

    private AuthenticationRequest getAuthRequest(SignedJWT requestObject) {
        var authRequestBuilder =
                new AuthenticationRequest.Builder(
                                new ResponseType(ResponseType.Value.CODE),
                                new Scope(OIDCScopeValue.OPENID, CustomScopeValue.DOC_CHECKING_APP),
                                CLIENT_ID,
                                URI.create(REDIRECT_URI))
                        .nonce(NONCE)
                        .state(STATE);

        if (Objects.nonNull(requestObject)) {
            authRequestBuilder.requestObject(requestObject);
        }
        return authRequestBuilder.build();
    }

    private SignedJWT generateSignedJWT(JWTClaimsSet jwtClaimsSet) throws JOSEException {
        var keyPair = generateRsaKeyPair();
        var jwsHeader = new JWSHeader(JWSAlgorithm.RS256);
        var signedJWT = new SignedJWT(jwsHeader, jwtClaimsSet);
        var signer = new RSASSASigner(keyPair.getPrivate());
        signedJWT.sign(signer);
        return signedJWT;
    }
}
