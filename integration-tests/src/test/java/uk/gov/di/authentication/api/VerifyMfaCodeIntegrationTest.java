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
import uk.gov.di.authentication.frontendapi.entity.VerifyMfaCodeRequest;
import uk.gov.di.authentication.frontendapi.lambda.VerifyMfaCodeHandler;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.MFAMethodType;
import uk.gov.di.authentication.shared.entity.ServiceType;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;
import uk.gov.di.authentication.sharedtest.helper.AuthAppStub;

import java.net.URI;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.CODE_MAX_RETRIES_REACHED;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.CODE_VERIFIED;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.INVALID_CODE_SENT;
import static uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper.assertEventTypesReceived;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class VerifyMfaCodeIntegrationTest extends ApiGatewayHandlerIntegrationTest {
    private static final String EMAIL_ADDRESS = "test@test.com";
    private static final String USER_PASSWORD = "TestPassword123!";
    private static final String CLIENT_ID = "test-client-id";
    private static final String REDIRECT_URI = "http://localhost/redirect";
    public static final String CLIENT_SESSION_ID = "a-client-session-id";
    private static final String AUTH_APP_SECRET_BASE_32 = "ORSXG5BNORSXQ5A=";
    private static final AuthAppStub AUTH_APP_STUB = new AuthAppStub();
    private String sessionId;

    @BeforeEach
    void beforeEachSetup() {
        handler = new VerifyMfaCodeHandler(TEST_CONFIGURATION_SERVICE);
        userStore.signUp(EMAIL_ADDRESS, USER_PASSWORD);

        try {
            this.sessionId = redis.createSession();
            setUpTestWithoutSignUp(sessionId, withScope());
        } catch (Json.JsonException e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    void whenValidAuthAppCodeReturn204() {
        userStore.addMfaMethod(
                EMAIL_ADDRESS, MFAMethodType.AUTH_APP, true, true, AUTH_APP_SECRET_BASE_32);
        String code = AUTH_APP_STUB.getAuthAppOneTimeCode(AUTH_APP_SECRET_BASE_32);
        VerifyMfaCodeRequest codeRequest =
                new VerifyMfaCodeRequest(MFAMethodType.AUTH_APP, code, true);

        var response =
                makeRequest(
                        Optional.of(codeRequest),
                        constructFrontendHeaders(sessionId, CLIENT_SESSION_ID),
                        Map.of());
        assertThat(response, hasStatus(204));

        assertEventTypesReceived(auditTopic, List.of(CODE_VERIFIED));
    }

    @Test
    void whenTwoMinuteOldValidAuthAppCodeReturn204() {
        userStore.addMfaMethod(
                EMAIL_ADDRESS, MFAMethodType.AUTH_APP, true, true, AUTH_APP_SECRET_BASE_32);
        long oneMinuteAgo = NowHelper.nowMinus(2, ChronoUnit.MINUTES).getTime();
        String code = AUTH_APP_STUB.getAuthAppOneTimeCode(AUTH_APP_SECRET_BASE_32, oneMinuteAgo);
        VerifyMfaCodeRequest codeRequest =
                new VerifyMfaCodeRequest(MFAMethodType.AUTH_APP, code, true);

        var response =
                makeRequest(
                        Optional.of(codeRequest),
                        constructFrontendHeaders(sessionId, CLIENT_SESSION_ID),
                        Map.of());

        assertThat(response, hasStatus(204));
        assertEventTypesReceived(auditTopic, List.of(CODE_VERIFIED));
    }

    @Test
    void whenFiveMinuteOldAuthAppCodeReturn400() {
        userStore.addMfaMethod(
                EMAIL_ADDRESS, MFAMethodType.AUTH_APP, true, true, AUTH_APP_SECRET_BASE_32);
        long tenMinutesAgo = NowHelper.nowMinus(5, ChronoUnit.MINUTES).getTime();
        String code = AUTH_APP_STUB.getAuthAppOneTimeCode(AUTH_APP_SECRET_BASE_32, tenMinutesAgo);
        VerifyMfaCodeRequest codeRequest =
                new VerifyMfaCodeRequest(MFAMethodType.AUTH_APP, code, true);

        var response =
                makeRequest(
                        Optional.of(codeRequest),
                        constructFrontendHeaders(sessionId, CLIENT_SESSION_ID),
                        Map.of());

        assertThat(response, hasStatus(400));
        assertEventTypesReceived(auditTopic, List.of(INVALID_CODE_SENT));
    }

    @Test
    void whenWrongSecretUsedByAuthAppReturn400() {
        userStore.addMfaMethod(
                EMAIL_ADDRESS, MFAMethodType.AUTH_APP, true, true, AUTH_APP_SECRET_BASE_32);
        String invalidCode = AUTH_APP_STUB.getAuthAppOneTimeCode("O5ZG63THFVZWKY3SMV2A====");
        VerifyMfaCodeRequest codeRequest =
                new VerifyMfaCodeRequest(MFAMethodType.AUTH_APP, invalidCode, true);

        var response =
                makeRequest(
                        Optional.of(codeRequest),
                        constructFrontendHeaders(sessionId, CLIENT_SESSION_ID),
                        Map.of());

        assertThat(response, hasStatus(400));
        assertThat(response, hasJsonBody(ErrorResponse.ERROR_1043));
        assertEventTypesReceived(auditTopic, List.of(INVALID_CODE_SENT));
    }

    @Test
    void whenAuthAppMfaMethodIsNotEnabledReturn400() {
        userStore.addMfaMethod(
                EMAIL_ADDRESS, MFAMethodType.AUTH_APP, true, false, AUTH_APP_SECRET_BASE_32);
        String code = AUTH_APP_STUB.getAuthAppOneTimeCode(AUTH_APP_SECRET_BASE_32);
        VerifyMfaCodeRequest codeRequest =
                new VerifyMfaCodeRequest(MFAMethodType.AUTH_APP, code, true);

        var response =
                makeRequest(
                        Optional.of(codeRequest),
                        constructFrontendHeaders(sessionId, CLIENT_SESSION_ID),
                        Map.of());

        assertThat(response, hasStatus(400));
        assertThat(response, hasJsonBody(ErrorResponse.ERROR_1043));
        assertEventTypesReceived(auditTopic, List.of(INVALID_CODE_SENT));
    }

    @Test
    void whenParametersMissingReturn400() {
        userStore.addMfaMethod(
                EMAIL_ADDRESS, MFAMethodType.AUTH_APP, true, true, AUTH_APP_SECRET_BASE_32);
        String code = AUTH_APP_STUB.getAuthAppOneTimeCode(AUTH_APP_SECRET_BASE_32);
        VerifyMfaCodeRequest codeRequest = new VerifyMfaCodeRequest(null, code, true);

        var response =
                makeRequest(
                        Optional.of(codeRequest),
                        constructFrontendHeaders(sessionId, CLIENT_SESSION_ID),
                        Map.of());

        assertThat(response, hasStatus(400));
        assertThat(response, hasJsonBody(ErrorResponse.ERROR_1001));
    }

    @Test
    void whenCodeSubmissionBlockedReturn400() {
        userStore.addMfaMethod(
                EMAIL_ADDRESS, MFAMethodType.AUTH_APP, true, true, AUTH_APP_SECRET_BASE_32);
        String code = AUTH_APP_STUB.getAuthAppOneTimeCode(AUTH_APP_SECRET_BASE_32);
        VerifyMfaCodeRequest codeRequest =
                new VerifyMfaCodeRequest(MFAMethodType.AUTH_APP, code, false);

        redis.blockMfaCodesForEmail(EMAIL_ADDRESS);

        var response =
                makeRequest(
                        Optional.of(codeRequest),
                        constructFrontendHeaders(sessionId, CLIENT_SESSION_ID),
                        Map.of());

        assertThat(response, hasStatus(400));
        assertThat(response, hasJsonBody(ErrorResponse.ERROR_1042));
        assertEventTypesReceived(auditTopic, List.of(CODE_MAX_RETRIES_REACHED));
    }

    @Test
    void whenCodeRetriesLimitExceededBlockEmailAndReturn400() throws Json.JsonException {
        userStore.addMfaMethod(
                EMAIL_ADDRESS, MFAMethodType.AUTH_APP, true, true, AUTH_APP_SECRET_BASE_32);
        String invalidCode = AUTH_APP_STUB.getAuthAppOneTimeCode("O5ZG63THFVZWKY3SMV2A====");
        VerifyMfaCodeRequest codeRequest =
                new VerifyMfaCodeRequest(MFAMethodType.AUTH_APP, invalidCode, false);

        for (int i = 0; i < 5; i++) {
            makeRequest(
                    Optional.of(codeRequest),
                    constructFrontendHeaders(sessionId, CLIENT_SESSION_ID),
                    Map.of());
        }

        var response =
                makeRequest(
                        Optional.of(codeRequest),
                        constructFrontendHeaders(sessionId, CLIENT_SESSION_ID),
                        Map.of());

        assertThat(response, hasStatus(400));
        assertThat(response, hasJsonBody(ErrorResponse.ERROR_1042));
        assertEquals(0, redis.getSession(sessionId).getRetryCount());
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

    private Scope withScope() {
        Scope scope = new Scope();
        scope.add(OIDCScopeValue.OPENID);
        scope.add(OIDCScopeValue.EMAIL);
        return scope;
    }
}
