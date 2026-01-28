package uk.gov.di.accountmanagement.api;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.accountmanagement.entity.AuthPolicy;
import uk.gov.di.accountmanagement.entity.TokenAuthorizerContext;
import uk.gov.di.accountmanagement.lambda.AuthoriseAccessTokenHandler;
import uk.gov.di.authentication.shared.entity.CustomScopeValue;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.sharedtest.basetest.HandlerIntegrationTest;
import uk.gov.di.authentication.sharedtest.extensions.TokenSigningExtension;

import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Supplier;

import static java.util.Arrays.asList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;

class AuthoriseAccessTokenIntegrationTest
        extends HandlerIntegrationTest<TokenAuthorizerContext, AuthPolicy> {

    @RegisterExtension
    protected static final TokenSigningExtension testTokenSigner =
            new TokenSigningExtension("test-token-signing-key");

    private static final ClientID CLIENT_ID = new ClientID();
    private static final String REQUEST_CONTEXT_OBJECT_CLIENT_ID_KEY = "clientId";
    private static final Subject PUBLIC_SUBJECT = new Subject();
    private Date validDate;

    private AuthPolicy makeRequest(String authToken) {
        var request =
                new TokenAuthorizerContext(
                        "TOKEN",
                        authToken,
                        "arn:aws:execute-api:region:12344566:hfmsi48564/test/$connect");

        return handler.handleRequest(request, context);
    }

    @BeforeEach
    void setup() {
        handler = new AuthoriseAccessTokenHandler(TEST_CONFIGURATION_SERVICE);
        validDate = NowHelper.nowPlus(5, ChronoUnit.MINUTES);
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

    @Test
    void shouldValidateTokenSignedWithTestKey() {
        var configServiceWithTestToken =
                new IntegrationTestConfigurationService(
                        notificationsQueue,
                        tokenSigner,
                        docAppPrivateKeyJwtSigner,
                        configurationParameters) {
                    @Override
                    public String getTestTokenSigningKeyAlias() {
                        return testTokenSigner.getKeyAlias();
                    }

                    @Override
                    public boolean isTestSigningKeyEnabled() {
                        return true;
                    }
                };

        var customHandler = new AuthoriseAccessTokenHandler(configServiceWithTestToken);

        var scopes =
                asList(
                        OIDCScopeValue.OPENID.getValue(),
                        CustomScopeValue.ACCOUNT_MANAGEMENT.getValue());

        var accessToken =
                generateSignedAccessTokenWithSigner(
                        testTokenSigner,
                        scopes,
                        Optional.of(CLIENT_ID.getValue()),
                        PUBLIC_SUBJECT.getValue(),
                        validDate);

        var request =
                new TokenAuthorizerContext(
                        "TOKEN",
                        accessToken.toAuthorizationHeader(),
                        "arn:aws:execute-api:region:12344566:hfmsi48564/test/$connect");

        var authPolicy = customHandler.handleRequest(request, context);

        assertThat(authPolicy.getPrincipalId(), equalTo(PUBLIC_SUBJECT.getValue()));
        assertThat(
                authPolicy.getContext().get(REQUEST_CONTEXT_OBJECT_CLIENT_ID_KEY),
                equalTo(CLIENT_ID.getValue()));
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
        return generateSignedAccessTokenWithSigner(
                tokenSigner, scopes, clientIdOpt, publicSubject, expiryDate);
    }

    private AccessToken generateSignedAccessTokenWithSigner(
            TokenSigningExtension signer,
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
        var signedJWT = signer.signJwt(claimsSetBuilder.build());
        return new BearerAccessToken(signedJWT.serialize());
    }
}
