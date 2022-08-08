package uk.gov.di.authentication.api;

import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.frontendapi.entity.VerifyCodeRequest;
import uk.gov.di.authentication.frontendapi.lambda.VerifyCodeHandler;
import uk.gov.di.authentication.shared.entity.ClientConsent;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.NotificationType;
import uk.gov.di.authentication.shared.entity.ServiceType;
import uk.gov.di.authentication.shared.entity.ValidScopes;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;

import java.net.URI;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.CODE_VERIFIED;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.INVALID_CODE_SENT;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_EMAIL;
import static uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper.assertEventTypesReceived;
import static uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper.assertNoAuditEventsReceived;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

public class VerifyCodeIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    private static final String EMAIL_ADDRESS = "test@test.com";
    private static final String CLIENT_ID = "test-client-id";
    private static final String REDIRECT_URI = "http://localhost/redirect";
    public static final String CLIENT_SESSION_ID = "a-client-session-id";

    @BeforeEach
    void setup() {
        handler = new VerifyCodeHandler(TEST_CONFIGURATION_SERVICE);
    }

    @Test
    void shouldCallVerifyCodeEndpointToVerifyEmailCodeAndReturn204() throws Json.JsonException {
        String sessionId = redis.createSession();
        setUpTestWithoutSignUp(sessionId, withScope());
        String code = redis.generateAndSaveEmailCode(EMAIL_ADDRESS, 900);
        VerifyCodeRequest codeRequest = new VerifyCodeRequest(VERIFY_EMAIL, code);

        var response =
                makeRequest(
                        Optional.of(codeRequest),
                        constructFrontendHeaders(sessionId, CLIENT_SESSION_ID),
                        Map.of());
        assertThat(response, hasStatus(204));

        assertEventTypesReceived(auditTopic, List.of(CODE_VERIFIED));
    }

    @Test
    void shouldResetCodeRequestCountWhenSuccessfulEmailCodeAndReturn204()
            throws Json.JsonException {
        var sessionId = redis.createSession();
        redis.incrementSessionCodeRequestCount(sessionId);
        redis.incrementSessionCodeRequestCount(sessionId);
        redis.incrementSessionCodeRequestCount(sessionId);
        setUpTestWithoutSignUp(sessionId, withScope());
        String code = redis.generateAndSaveEmailCode(EMAIL_ADDRESS, 900);
        VerifyCodeRequest codeRequest = new VerifyCodeRequest(VERIFY_EMAIL, code);

        var response =
                makeRequest(
                        Optional.of(codeRequest),
                        constructFrontendHeaders(sessionId, CLIENT_SESSION_ID),
                        Map.of());

        assertThat(response, hasStatus(204));
        assertThat(redis.getMfaCodeAttemptsCount(EMAIL_ADDRESS), equalTo(0));
        assertEventTypesReceived(auditTopic, List.of(CODE_VERIFIED));
    }

    @Test
    void shouldCallVerifyCodeEndpointAndReturn400WhenEmailCodeHasExpired()
            throws InterruptedException, Json.JsonException {
        String sessionId = redis.createSession();
        setUpTestWithoutSignUp(sessionId, withScope());

        String code = redis.generateAndSaveEmailCode(EMAIL_ADDRESS, 2);
        VerifyCodeRequest codeRequest = new VerifyCodeRequest(VERIFY_EMAIL, code);

        TimeUnit.SECONDS.sleep(3);

        var response =
                makeRequest(
                        Optional.of(codeRequest),
                        constructFrontendHeaders(sessionId, CLIENT_SESSION_ID),
                        Map.of());

        assertThat(response, hasStatus(400));
        assertThat(response, hasJsonBody(ErrorResponse.ERROR_1036));

        assertEventTypesReceived(auditTopic, List.of(INVALID_CODE_SENT));
    }

    @Test
    void shouldReturn400WithErrorWhenUserTriesEmailCodeThatTheyHaveAlreadyUsed()
            throws Json.JsonException {
        String sessionId = redis.createSession();
        setUpTestWithoutSignUp(sessionId, withScope());
        String code = redis.generateAndSaveEmailCode(EMAIL_ADDRESS, 900);
        VerifyCodeRequest codeRequest = new VerifyCodeRequest(VERIFY_EMAIL, code);

        var response =
                makeRequest(
                        Optional.of(codeRequest),
                        constructFrontendHeaders(sessionId, CLIENT_SESSION_ID),
                        Map.of());

        assertThat(response, hasStatus(204));

        var response2 =
                makeRequest(
                        Optional.of(codeRequest),
                        constructFrontendHeaders(sessionId, CLIENT_SESSION_ID),
                        Map.of());

        assertThat(response2, hasStatus(400));
        assertThat(response2, hasJsonBody(ErrorResponse.ERROR_1036));

        assertEventTypesReceived(auditTopic, List.of(CODE_VERIFIED, INVALID_CODE_SENT));
    }

    @Test
    void shouldCallVerifyCodeEndpointToVerifyPhoneCodeAndReturn204() throws Json.JsonException {
        String sessionId = redis.createSession();
        Scope scope = withScope();
        setUpTestWithoutClientConsent(sessionId, scope);
        Set<String> claims = ValidScopes.getClaimsForListOfScopes(scope.toStringList());
        ClientConsent clientConsent =
                new ClientConsent(
                        CLIENT_ID, claims, LocalDateTime.now(ZoneId.of("UTC")).toString());
        userStore.updateConsent(EMAIL_ADDRESS, clientConsent);
        String code = redis.generateAndSavePhoneNumberCode(EMAIL_ADDRESS, 900);
        VerifyCodeRequest codeRequest =
                new VerifyCodeRequest(NotificationType.VERIFY_PHONE_NUMBER, code);

        var response =
                makeRequest(
                        Optional.of(codeRequest),
                        constructFrontendHeaders(sessionId, CLIENT_SESSION_ID),
                        Map.of());

        assertThat(response, hasStatus(204));
        assertEventTypesReceived(auditTopic, List.of(CODE_VERIFIED));
    }

    @Test
    void shouldResetCodeRequestCountWhenSuccessfulVerifyPhoneCodeAndReturn204()
            throws Json.JsonException {
        String sessionId = redis.createSession();
        redis.incrementSessionCodeRequestCount(sessionId);
        redis.incrementSessionCodeRequestCount(sessionId);
        redis.incrementSessionCodeRequestCount(sessionId);
        Scope scope = withScope();
        setUpTestWithoutClientConsent(sessionId, scope);
        Set<String> claims = ValidScopes.getClaimsForListOfScopes(scope.toStringList());
        ClientConsent clientConsent =
                new ClientConsent(
                        CLIENT_ID, claims, LocalDateTime.now(ZoneId.of("UTC")).toString());
        userStore.updateConsent(EMAIL_ADDRESS, clientConsent);
        String code = redis.generateAndSavePhoneNumberCode(EMAIL_ADDRESS, 900);
        VerifyCodeRequest codeRequest =
                new VerifyCodeRequest(NotificationType.VERIFY_PHONE_NUMBER, code);

        var response =
                makeRequest(
                        Optional.of(codeRequest),
                        constructFrontendHeaders(sessionId, CLIENT_SESSION_ID),
                        Map.of());


        assertThat(response, hasStatus(204));
        assertThat(redis.getMfaCodeAttemptsCount(EMAIL_ADDRESS), equalTo(0));
        assertEventTypesReceived(auditTopic, List.of(CODE_VERIFIED));
    }

    @Test
    void shouldCallVerifyCodeEndpointAndReturn400WithErrorWhenPhoneNumberCodeHasExpired()
            throws InterruptedException, Json.JsonException {
        String sessionId = redis.createSession();
        setUpTestWithoutSignUp(sessionId, withScope());

        String code = redis.generateAndSavePhoneNumberCode(EMAIL_ADDRESS, 2);
        VerifyCodeRequest codeRequest =
                new VerifyCodeRequest(NotificationType.VERIFY_PHONE_NUMBER, code);

        TimeUnit.SECONDS.sleep(3);

        var response =
                makeRequest(
                        Optional.of(codeRequest),
                        constructFrontendHeaders(sessionId, CLIENT_SESSION_ID),
                        Map.of());

        assertThat(response, hasStatus(400));
        assertThat(response, hasJsonBody(ErrorResponse.ERROR_1037));

        assertEventTypesReceived(auditTopic, List.of(INVALID_CODE_SENT));
    }

    @Test
    void shouldReturnMaxCodesReachedIfPhoneNumberCodeIsBlocked() throws Json.JsonException {
        String sessionId = redis.createSession();
        redis.addEmailToSession(sessionId, EMAIL_ADDRESS);
        redis.blockMfaCodesForEmail(EMAIL_ADDRESS);

        VerifyCodeRequest codeRequest =
                new VerifyCodeRequest(NotificationType.VERIFY_PHONE_NUMBER, "123456");

        var response =
                makeRequest(
                        Optional.of(codeRequest), constructFrontendHeaders(sessionId), Map.of());

        assertThat(response, hasStatus(400));
        assertThat(response, hasJsonBody(ErrorResponse.ERROR_1034));

        assertNoAuditEventsReceived(auditTopic);
    }

    @Test
    void shouldReturnMaxCodesReachedIfEmailCodeIsBlocked() throws Json.JsonException {
        String sessionId = redis.createSession();
        redis.addEmailToSession(sessionId, EMAIL_ADDRESS);
        redis.blockMfaCodesForEmail(EMAIL_ADDRESS);

        VerifyCodeRequest codeRequest = new VerifyCodeRequest(VERIFY_EMAIL, "123456");

        var response =
                makeRequest(
                        Optional.of(codeRequest), constructFrontendHeaders(sessionId), Map.of());

        assertThat(response, hasStatus(400));
        assertThat(response, hasJsonBody(ErrorResponse.ERROR_1033));

        assertNoAuditEventsReceived(auditTopic);
    }

    @Test
    void shouldReturn204WhenUserHasAcceptedCurrentTermsAndConditions() throws Exception {
        String sessionId = redis.createSession();
        Scope scope = new Scope();
        scope.add(OIDCScopeValue.OPENID);
        scope.add(OIDCScopeValue.EMAIL);
        scope.add(OIDCScopeValue.PHONE);
        setUpTestWithoutClientConsent(sessionId, withScope());
        userStore.updateTermsAndConditions(EMAIL_ADDRESS, "1.0");
        ClientConsent clientConsent =
                new ClientConsent(
                        CLIENT_ID,
                        ValidScopes.getClaimsForListOfScopes(scope.toStringList()),
                        LocalDateTime.now().toString());
        userStore.updateConsent(EMAIL_ADDRESS, clientConsent);

        String code = redis.generateAndSaveMfaCode(EMAIL_ADDRESS, 900);
        VerifyCodeRequest codeRequest = new VerifyCodeRequest(NotificationType.MFA_SMS, code);

        var response =
                makeRequest(
                        Optional.of(codeRequest),
                        constructFrontendHeaders(sessionId, CLIENT_SESSION_ID),
                        Map.of());

        assertThat(response, hasStatus(204));
        assertEventTypesReceived(auditTopic, List.of(CODE_VERIFIED));
    }

    private void setUpTestWithoutSignUp(String sessionId, Scope scope) throws Json.JsonException {
        redis.addEmailToSession(sessionId, EMAIL_ADDRESS);
        AuthenticationRequest authRequest =
                new AuthenticationRequest.Builder(
                                ResponseType.CODE,
                                scope,
                                new ClientID(CLIENT_ID),
                                URI.create(REDIRECT_URI))
                        .nonce(new Nonce())
                        .state(new State())
                        .build();
        redis.createClientSession(CLIENT_SESSION_ID, authRequest.toParameters());
        clientStore.registerClient(
                CLIENT_ID,
                "test-client",
                singletonList("redirect-url"),
                singletonList(EMAIL_ADDRESS),
                List.of("openid", "email", "phone"),
                "public-key",
                singletonList("http://localhost/post-redirect-logout"),
                "http://example.com",
                String.valueOf(ServiceType.MANDATORY),
                "https://test.com",
                "public",
                true);
    }

    private void setUpTestWithoutClientConsent(String sessionId, Scope scope)
            throws Json.JsonException {
        setUpTestWithoutSignUp(sessionId, scope);
        userStore.signUp(EMAIL_ADDRESS, "password");
    }

    private Scope withScope() {
        Scope scope = new Scope();
        scope.add(OIDCScopeValue.OPENID);
        scope.add(OIDCScopeValue.EMAIL);
        return scope;
    }
}
