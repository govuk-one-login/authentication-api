package uk.gov.di.accountmanagement.api;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.accountmanagement.entity.AuthPolicy;
import uk.gov.di.accountmanagement.entity.TokenAuthorizerContext;
import uk.gov.di.accountmanagement.lambda.AuthoriseAccessTokenHandler;
import uk.gov.di.authentication.shared.entity.CustomScopeValue;
import uk.gov.di.authentication.shared.entity.ServiceType;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.sharedtest.basetest.HandlerIntegrationTest;
import uk.gov.di.authentication.sharedtest.helper.KeyPairHelper;

import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.util.function.Supplier;

import static java.util.Arrays.asList;
import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;

class AuthoriseAccessTokenIntegrationTest
        extends HandlerIntegrationTest<TokenAuthorizerContext, AuthPolicy> {

    private static final ClientID CLIENT_ID = new ClientID();
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
        var publicSubject = setUpUserProfileAndGetPublicSubjectId();
        var scopes =
                asList(
                        OIDCScopeValue.OPENID.getValue(),
                        CustomScopeValue.ACCOUNT_MANAGEMENT.getValue());
        var accessToken =
                generateSignedAccessToken(scopes, CLIENT_ID.getValue(), publicSubject, validDate);
        setUpClient(scopes);

        var authPolicy = makeRequest(accessToken.toAuthorizationHeader());

        assertThat(authPolicy.getPrincipalId(), equalTo(publicSubject));
    }

    @Test
    void shouldThrowExceptionWhenAccessTokenHasExpired() {
        var publicSubject = setUpUserProfileAndGetPublicSubjectId();
        var expiryDate = NowHelper.nowMinus(1, ChronoUnit.MINUTES);
        var scopes =
                asList(
                        OIDCScopeValue.OPENID.getValue(),
                        CustomScopeValue.ACCOUNT_MANAGEMENT.getValue());
        var accessToken =
                generateSignedAccessToken(scopes, CLIENT_ID.getValue(), publicSubject, expiryDate);
        setUpClient(scopes);

        expectException(() -> makeRequest(accessToken.toAuthorizationHeader()));
    }

    @Test
    void shouldThrowExceptionWhenAccessTokenIsMissingAmScope() {
        var publicSubject = setUpUserProfileAndGetPublicSubjectId();
        var scopes = List.of(OIDCScopeValue.OPENID.getValue());
        var accessToken =
                generateSignedAccessToken(scopes, CLIENT_ID.getValue(), publicSubject, validDate);
        setUpClient(scopes);

        expectException(() -> makeRequest(accessToken.toAuthorizationHeader()));
    }

    @Test
    void shouldThrowExceptionWhenAccessTokenHasInvalidClientId() {
        var publicSubject = setUpUserProfileAndGetPublicSubjectId();
        var scopes =
                asList(
                        OIDCScopeValue.OPENID.getValue(),
                        CustomScopeValue.ACCOUNT_MANAGEMENT.getValue());
        var accessToken =
                generateSignedAccessToken(scopes, "rubbish-client-id", publicSubject, validDate);
        setUpClient(scopes);

        expectException(() -> makeRequest(accessToken.toAuthorizationHeader()));
    }

    @Test
    void shouldThrowExceptionWhenAccessTokenHasUnknownSubject() {
        var publicSubject = new Subject().getValue();
        var scopes =
                asList(
                        OIDCScopeValue.OPENID.getValue(),
                        CustomScopeValue.ACCOUNT_MANAGEMENT.getValue());
        var accessToken =
                generateSignedAccessToken(scopes, CLIENT_ID.getValue(), publicSubject, validDate);
        setUpClient(scopes);

        setUpClient(scopes);

        expectException(() -> makeRequest(accessToken.toAuthorizationHeader()));
    }

    private void expectException(Supplier<AuthPolicy> performAction) {
        var ex = assertThrows(RuntimeException.class, performAction::get);

        assertThat(ex.getMessage(), is("Unauthorized"));
    }

    private String setUpUserProfileAndGetPublicSubjectId() {
        return userStore.signUp("jim@test.com", "password", new Subject());
    }

    private void setUpClient(List<String> scopes) {
        var keyPair = KeyPairHelper.GENERATE_RSA_KEY_PAIR();
        clientStore.registerClient(
                CLIENT_ID.getValue(),
                "test-client",
                singletonList("redirect-url"),
                singletonList("joe.bloggs@digital.cabinet-office.gov.uk"),
                scopes,
                Base64.getMimeEncoder().encodeToString(keyPair.getPublic().getEncoded()),
                singletonList("http://localhost/post-redirect-logout"),
                "http://example.com",
                String.valueOf(ServiceType.MANDATORY),
                "https://test.com",
                "public",
                true);
    }

    private AccessToken generateSignedAccessToken(
            List<String> scopes, String clientId, String publicSubject, Date expiryDate) {
        var claimsSet =
                new JWTClaimsSet.Builder()
                        .claim("scope", scopes)
                        .issuer("issuer-id")
                        .expirationTime(expiryDate)
                        .issueTime(NowHelper.now())
                        .claim("client_id", clientId)
                        .subject(publicSubject)
                        .jwtID(UUID.randomUUID().toString())
                        .build();
        var signedJWT = tokenSigner.signJwt(claimsSet);
        return new BearerAccessToken(signedJWT.serialize());
    }
}
