package uk.gov.di.accountmanagement.api;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.accountmanagement.entity.AuthPolicy;
import uk.gov.di.accountmanagement.entity.TokenAuthorizerContext;
import uk.gov.di.accountmanagement.lambda.AuthoriseAccessTokenHandler;
import uk.gov.di.authentication.shared.entity.CustomScopeValue;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.sharedtest.basetest.HandlerIntegrationTest;
import uk.gov.di.authentication.sharedtest.extensions.JwksExtension;
import uk.org.webcompere.systemstubs.environment.EnvironmentVariables;
import uk.org.webcompere.systemstubs.jupiter.SystemStub;
import uk.org.webcompere.systemstubs.jupiter.SystemStubsExtension;

import java.net.MalformedURLException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPublicKey;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Supplier;

import static com.nimbusds.jose.jwk.Curve.P_256;
import static java.util.Arrays.asList;
import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;

@ExtendWith(SystemStubsExtension.class)
class AuthoriseAccessTokenIntegrationTest
        extends HandlerIntegrationTest<TokenAuthorizerContext, AuthPolicy> {

    private static final ClientID CLIENT_ID = new ClientID();
    private static final String REQUEST_CONTEXT_OBJECT_CLIENT_ID_KEY = "clientId";
    private static final Subject PUBLIC_SUBJECT = new Subject();
    private static KeyPair ecKeyPair;
    private Date validDate;

    @RegisterExtension public static final JwksExtension jwksExtension = new JwksExtension();

    @SystemStub static EnvironmentVariables environment = new EnvironmentVariables();

    private AuthPolicy makeRequest(String authToken) {
        var request =
                new TokenAuthorizerContext(
                        "TOKEN",
                        authToken,
                        "arn:aws:execute-api:region:12344566:hfmsi48564/test/$connect");

        return handler.handleRequest(request, context);
    }

    @BeforeAll
    static void setupEnvironment() throws MalformedURLException {
        environment.set("ACCESS_TOKEN_JWKS_URL", jwksExtension.getJwksUrl());
    }

    @BeforeEach
    void setup() {
        handler = new AuthoriseAccessTokenHandler(TEST_CONFIGURATION_SERVICE_JWKS_DISABLED);
        validDate = NowHelper.nowPlus(5, ChronoUnit.MINUTES);
    }

    private static KeyPair createTestEncryptionKeyPair() {
        try {
            var keyPairGenerator = KeyPairGenerator.getInstance("EC");
            keyPairGenerator.initialize(256);
            return keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Unable to create EC key pair: " + e.getMessage());
        }
    }

    @Test
    void shouldReturnAuthPolicyForSuccessfulRequest() {
        var scopes =
                asList(
                        OIDCScopeValue.OPENID.getValue(),
                        CustomScopeValue.ACCOUNT_MANAGEMENT.getValue());
        var accessToken =
                generateSignedAccessToken(
                        scopes,
                        Optional.of(CLIENT_ID.getValue()),
                        PUBLIC_SUBJECT.getValue(),
                        validDate);

        var authPolicy = makeRequest(accessToken.toAuthorizationHeader());

        assertThat(authPolicy.getPrincipalId(), equalTo(PUBLIC_SUBJECT.getValue()));
        assertThat(
                authPolicy.getContext().get(REQUEST_CONTEXT_OBJECT_CLIENT_ID_KEY),
                equalTo(CLIENT_ID.getValue()));
    }

    @Test
    void shouldReturnAuthPolicyForSuccessfulRequestWithJwksEnabled() throws JOSEException {
        handler = new AuthoriseAccessTokenHandler(TEST_CONFIGURATION_SERVICE_JWKS_ENABLED);
        ecKeyPair = createTestEncryptionKeyPair();
        JWKSet jwkSet =
                new JWKSet(
                        singletonList(
                                new ECKey.Builder(P_256, (ECPublicKey) ecKeyPair.getPublic())
                                        .privateKey(ecKeyPair.getPrivate())
                                        .keyID(
                                                TEST_CONFIGURATION_SERVICE_JWKS_ENABLED
                                                        .getTokenSigningKeyId())
                                        .keyUse(KeyUse.SIGNATURE)
                                        .algorithm(JWSAlgorithm.ES256)
                                        .build()));
        jwksExtension.init(jwkSet);

        var scopes =
                asList(
                        OIDCScopeValue.OPENID.getValue(),
                        CustomScopeValue.ACCOUNT_MANAGEMENT.getValue());
        var accessToken =
                generateSignedAccessTokenWithoutKms(
                        scopes,
                        Optional.of(CLIENT_ID.getValue()),
                        PUBLIC_SUBJECT.getValue(),
                        validDate);

        var authPolicy = makeRequest(accessToken.toAuthorizationHeader());

        assertThat(authPolicy.getPrincipalId(), equalTo(PUBLIC_SUBJECT.getValue()));
        assertThat(
                authPolicy.getContext().get(REQUEST_CONTEXT_OBJECT_CLIENT_ID_KEY),
                equalTo(CLIENT_ID.getValue()));
    }

    @Test
    void shouldThrowExceptionWhenAccessTokenHasExpired() {
        var expiryDate = NowHelper.nowMinus(1, ChronoUnit.MINUTES);
        var scopes =
                asList(
                        OIDCScopeValue.OPENID.getValue(),
                        CustomScopeValue.ACCOUNT_MANAGEMENT.getValue());
        var accessToken =
                generateSignedAccessToken(
                        scopes,
                        Optional.of(CLIENT_ID.getValue()),
                        PUBLIC_SUBJECT.getValue(),
                        expiryDate);

        expectException(() -> makeRequest(accessToken.toAuthorizationHeader()));
    }

    @Test
    void shouldThrowExceptionWhenAccessTokenIsMissingAmScope() {
        var scopes = List.of(OIDCScopeValue.OPENID.getValue());
        var accessToken =
                generateSignedAccessToken(
                        scopes,
                        Optional.of(CLIENT_ID.getValue()),
                        PUBLIC_SUBJECT.getValue(),
                        validDate);

        expectException(() -> makeRequest(accessToken.toAuthorizationHeader()));
    }

    @Test
    void shouldThrowExceptionWhenAccessTokenHasMissingClientId() {
        var scopes =
                asList(
                        OIDCScopeValue.OPENID.getValue(),
                        CustomScopeValue.ACCOUNT_MANAGEMENT.getValue());
        var accessToken =
                generateSignedAccessToken(
                        scopes, Optional.empty(), PUBLIC_SUBJECT.getValue(), validDate);

        expectException(() -> makeRequest(accessToken.toAuthorizationHeader()));
    }

    private void expectException(Supplier<AuthPolicy> performAction) {
        var ex = assertThrows(RuntimeException.class, performAction::get);

        assertThat(ex.getMessage(), is("Unauthorized"));
    }

    private AccessToken generateSignedAccessToken(
            List<String> scopes,
            Optional<String> clientIdOpt,
            String publicSubject,
            Date expiryDate) {
        var claimsSetBuilder =
                new JWTClaimsSet.Builder()
                        .claim("scope", scopes)
                        .issuer("issuer-id")
                        .expirationTime(expiryDate)
                        .issueTime(NowHelper.now())
                        .subject(publicSubject)
                        .jwtID(UUID.randomUUID().toString());
        clientIdOpt.ifPresent(clientId -> claimsSetBuilder.claim("client_id", clientId));
        var signedJWT = tokenSigner.signJwt(claimsSetBuilder.build());
        return new BearerAccessToken(signedJWT.serialize());
    }

    private AccessToken generateSignedAccessTokenWithoutKms(
            List<String> scopes,
            Optional<String> clientIdOpt,
            String publicSubject,
            Date expiryDate)
            throws JOSEException {
        var claimsSetBuilder =
                new JWTClaimsSet.Builder()
                        .claim("scope", scopes)
                        .issuer("issuer-id")
                        .expirationTime(expiryDate)
                        .issueTime(NowHelper.now())
                        .subject(publicSubject)
                        .jwtID(UUID.randomUUID().toString());
        clientIdOpt.ifPresent(clientId -> claimsSetBuilder.claim("client_id", clientId));
        var signedJWT = tokenSigner.signJwtWithoutKms(claimsSetBuilder.build(), ecKeyPair);
        return new BearerAccessToken(signedJWT.serialize());
    }
}
