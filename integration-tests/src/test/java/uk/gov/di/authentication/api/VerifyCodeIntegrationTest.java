package uk.gov.di.authentication.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.frontendapi.entity.VerifyCodeRequest;
import uk.gov.di.authentication.helpers.DynamoHelper;
import uk.gov.di.authentication.helpers.RedisHelper;
import uk.gov.di.authentication.helpers.RequestHelper;
import uk.gov.di.authentication.shared.entity.BaseAPIResponse;
import uk.gov.di.authentication.shared.entity.ClientConsent;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.NotificationType;
import uk.gov.di.authentication.shared.entity.ServiceType;
import uk.gov.di.authentication.shared.entity.SessionState;
import uk.gov.di.authentication.shared.entity.ValidScopes;

import java.io.IOException;
import java.net.URI;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import static java.util.Collections.singletonList;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_EMAIL;

public class VerifyCodeIntegrationTest extends IntegrationTestEndpoints {

    private static final String VERIFY_CODE_ENDPOINT = "/verify-code";
    private static final String EMAIL_ADDRESS = "test@test.com";
    private static final String CLIENT_ID = "test-client-id";
    private static final String REDIRECT_URI = "http://localhost/redirect";
    public static final String CLIENT_SESSION_ID = "a-client-session-id";
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    public void shouldCallVerifyCodeEndpointToVerifyEmailCodeAndReturn200() throws IOException {
        String sessionId = RedisHelper.createSession();
        setUpTestWithoutSignUp(sessionId, withScope(), SessionState.VERIFY_EMAIL_CODE_SENT);
        String code = RedisHelper.generateAndSaveEmailCode(EMAIL_ADDRESS, 900);
        VerifyCodeRequest codeRequest = new VerifyCodeRequest(VERIFY_EMAIL, code);

        Response response =
                RequestHelper.request(
                        FRONTEND_ROOT_RESOURCE_URL,
                        VERIFY_CODE_ENDPOINT,
                        codeRequest,
                        withHeaders(sessionId));

        assertEquals(200, response.getStatus());
    }

    @Test
    public void shouldCallVerifyCodeEndpointAndReturn400WitUpdatedStateWhenEmailCodeHasExpired()
            throws IOException, InterruptedException {
        String sessionId = RedisHelper.createSession();
        setUpTestWithoutSignUp(sessionId, withScope(), SessionState.VERIFY_EMAIL_CODE_SENT);

        String code = RedisHelper.generateAndSaveEmailCode(EMAIL_ADDRESS, 2);
        VerifyCodeRequest codeRequest = new VerifyCodeRequest(VERIFY_EMAIL, code);

        TimeUnit.SECONDS.sleep(3);

        Response response =
                RequestHelper.request(
                        FRONTEND_ROOT_RESOURCE_URL,
                        VERIFY_CODE_ENDPOINT,
                        codeRequest,
                        withHeaders(sessionId));

        assertEquals(400, response.getStatus());
        BaseAPIResponse codeResponse =
                objectMapper.readValue(response.readEntity(String.class), BaseAPIResponse.class);
        assertEquals(SessionState.EMAIL_CODE_NOT_VALID, codeResponse.getSessionState());
    }

    @Test
    public void shouldReturn400WithNewStateWhenUserTriesEmailCodeThatTheyHaveAlreadyUsed()
            throws IOException {
        String sessionId = RedisHelper.createSession();
        setUpTestWithoutSignUp(sessionId, withScope(), SessionState.VERIFY_EMAIL_CODE_SENT);
        String code = RedisHelper.generateAndSaveEmailCode(EMAIL_ADDRESS, 900);
        VerifyCodeRequest codeRequest = new VerifyCodeRequest(VERIFY_EMAIL, code);

        Response response =
                RequestHelper.request(
                        FRONTEND_ROOT_RESOURCE_URL,
                        VERIFY_CODE_ENDPOINT,
                        codeRequest,
                        withHeaders(sessionId));

        assertEquals(200, response.getStatus());
        BaseAPIResponse codeResponse1 =
                objectMapper.readValue(response.readEntity(String.class), BaseAPIResponse.class);
        assertEquals(SessionState.EMAIL_CODE_VERIFIED, codeResponse1.getSessionState());

        Response response2 =
                RequestHelper.request(
                        FRONTEND_ROOT_RESOURCE_URL,
                        VERIFY_CODE_ENDPOINT,
                        codeRequest,
                        withHeaders(sessionId));

        assertEquals(400, response2.getStatus());

        BaseAPIResponse codeResponse =
                objectMapper.readValue(response2.readEntity(String.class), BaseAPIResponse.class);
        assertEquals(SessionState.EMAIL_CODE_NOT_VALID, codeResponse.getSessionState());
    }

    @Test
    public void shouldCallVerifyCodeEndpointToVerifyPhoneCodeAndReturn200() throws IOException {
        String sessionId = RedisHelper.createSession();
        Scope scope = withScope();
        setUpTestWithoutClientConsent(sessionId, scope, SessionState.VERIFY_PHONE_NUMBER_CODE_SENT);
        Set<String> claims = ValidScopes.getClaimsForListOfScopes(scope.toStringList());
        ClientConsent clientConsent =
                new ClientConsent(
                        CLIENT_ID, claims, LocalDateTime.now(ZoneId.of("UTC")).toString());
        DynamoHelper.updateConsent(EMAIL_ADDRESS, clientConsent);
        String code = RedisHelper.generateAndSavePhoneNumberCode(EMAIL_ADDRESS, 900);
        VerifyCodeRequest codeRequest =
                new VerifyCodeRequest(NotificationType.VERIFY_PHONE_NUMBER, code);

        Response response =
                RequestHelper.request(
                        FRONTEND_ROOT_RESOURCE_URL,
                        VERIFY_CODE_ENDPOINT,
                        codeRequest,
                        withHeaders(sessionId));

        assertEquals(200, response.getStatus());
        BaseAPIResponse codeResponse =
                objectMapper.readValue(response.readEntity(String.class), BaseAPIResponse.class);
        assertEquals(SessionState.PHONE_NUMBER_CODE_VERIFIED, codeResponse.getSessionState());
    }

    @Test
    public void shouldCallVerifyCodeEndpointToVerifyPhoneCodeAndReturnConsentRequiredState()
            throws IOException {
        String sessionId = RedisHelper.createSession();
        setUpTestWithoutClientConsent(
                sessionId, withScope(), SessionState.VERIFY_PHONE_NUMBER_CODE_SENT);
        String code = RedisHelper.generateAndSavePhoneNumberCode(EMAIL_ADDRESS, 900);
        VerifyCodeRequest codeRequest =
                new VerifyCodeRequest(NotificationType.VERIFY_PHONE_NUMBER, code);

        Response response =
                RequestHelper.request(
                        FRONTEND_ROOT_RESOURCE_URL,
                        VERIFY_CODE_ENDPOINT,
                        codeRequest,
                        withHeaders(sessionId));

        assertEquals(200, response.getStatus());
        BaseAPIResponse codeResponse =
                objectMapper.readValue(response.readEntity(String.class), BaseAPIResponse.class);
        assertEquals(SessionState.CONSENT_REQUIRED, codeResponse.getSessionState());
    }

    @Test
    public void
            shouldCallVerifyCodeEndpointAndReturn400WitUpdatedStateWhenPhoneNumberCodeHasExpired()
                    throws IOException, InterruptedException {
        String sessionId = RedisHelper.createSession();
        setUpTestWithoutSignUp(sessionId, withScope(), SessionState.VERIFY_PHONE_NUMBER_CODE_SENT);

        String code = RedisHelper.generateAndSavePhoneNumberCode(EMAIL_ADDRESS, 2);
        VerifyCodeRequest codeRequest =
                new VerifyCodeRequest(NotificationType.VERIFY_PHONE_NUMBER, code);

        TimeUnit.SECONDS.sleep(3);

        Response response =
                RequestHelper.request(
                        FRONTEND_ROOT_RESOURCE_URL,
                        VERIFY_CODE_ENDPOINT,
                        codeRequest,
                        withHeaders(sessionId));

        assertEquals(400, response.getStatus());

        BaseAPIResponse codeResponse =
                objectMapper.readValue(response.readEntity(String.class), BaseAPIResponse.class);
        assertEquals(SessionState.PHONE_NUMBER_CODE_NOT_VALID, codeResponse.getSessionState());
    }

    @Test
    public void shouldReturnMaxCodesReachedIfPhoneNumberCodeIsBlocked() throws IOException {
        String sessionId = RedisHelper.createSession();
        RedisHelper.addEmailToSession(sessionId, EMAIL_ADDRESS);
        RedisHelper.setSessionState(sessionId, SessionState.PHONE_NUMBER_CODE_NOT_VALID);
        RedisHelper.blockPhoneCode(EMAIL_ADDRESS, sessionId);
        MultivaluedMap<String, Object> headers = new MultivaluedHashMap<>();
        headers.add("Session-Id", sessionId);
        headers.add("X-API-Key", FRONTEND_API_KEY);

        VerifyCodeRequest codeRequest =
                new VerifyCodeRequest(NotificationType.VERIFY_PHONE_NUMBER, "123456");

        Response response =
                RequestHelper.request(
                        FRONTEND_ROOT_RESOURCE_URL, VERIFY_CODE_ENDPOINT, codeRequest, headers);

        assertEquals(400, response.getStatus());

        BaseAPIResponse codeResponse =
                objectMapper.readValue(response.readEntity(String.class), BaseAPIResponse.class);
        assertEquals(
                SessionState.PHONE_NUMBER_CODE_MAX_RETRIES_REACHED, codeResponse.getSessionState());
    }

    @Test
    public void shouldReturnMaxCodesReachedIfEmailCodeIsBlocked() throws IOException {
        String sessionId = RedisHelper.createSession();
        RedisHelper.setSessionState(sessionId, SessionState.EMAIL_CODE_NOT_VALID);
        RedisHelper.addEmailToSession(sessionId, EMAIL_ADDRESS);
        RedisHelper.blockPhoneCode(EMAIL_ADDRESS, sessionId);
        MultivaluedMap<String, Object> headers = new MultivaluedHashMap<>();
        headers.add("Session-Id", sessionId);
        headers.add("X-API-Key", FRONTEND_API_KEY);

        VerifyCodeRequest codeRequest = new VerifyCodeRequest(VERIFY_EMAIL, "123456");

        Response response =
                RequestHelper.request(
                        FRONTEND_ROOT_RESOURCE_URL, VERIFY_CODE_ENDPOINT, codeRequest, headers);

        assertEquals(400, response.getStatus());

        BaseAPIResponse codeResponse =
                objectMapper.readValue(response.readEntity(String.class), BaseAPIResponse.class);
        assertEquals(SessionState.EMAIL_CODE_MAX_RETRIES_REACHED, codeResponse.getSessionState());
    }

    @Test
    public void shouldReturn400IfStateTransitionIsInvalid() throws IOException {
        String sessionId = RedisHelper.createSession();
        setUpTestWithoutSignUp(sessionId, withScope(), SessionState.NEW);

        String code = RedisHelper.generateAndSaveEmailCode(EMAIL_ADDRESS, 900);
        VerifyCodeRequest codeRequest = new VerifyCodeRequest(VERIFY_EMAIL, code);

        Response response =
                RequestHelper.request(
                        FRONTEND_ROOT_RESOURCE_URL,
                        VERIFY_CODE_ENDPOINT,
                        codeRequest,
                        withHeaders(sessionId));

        assertEquals(400, response.getStatus());
        assertEquals(
                new ObjectMapper().writeValueAsString(ErrorResponse.ERROR_1017),
                response.readEntity(String.class));
    }

    @Test
    public void shouldReturn400IfStateTransitionIsInvalid_PhoneNumber() throws IOException {
        String sessionId = RedisHelper.createSession();
        setUpTestWithoutSignUp(sessionId, withScope(), SessionState.NEW);

        String code = RedisHelper.generateAndSavePhoneNumberCode(EMAIL_ADDRESS, 900);
        VerifyCodeRequest codeRequest =
                new VerifyCodeRequest(NotificationType.VERIFY_PHONE_NUMBER, code);
        DynamoHelper.signUp(EMAIL_ADDRESS, "password");

        Response response =
                RequestHelper.request(
                        FRONTEND_ROOT_RESOURCE_URL,
                        VERIFY_CODE_ENDPOINT,
                        codeRequest,
                        withHeaders(sessionId));

        assertEquals(400, response.getStatus());
        assertEquals(
                new ObjectMapper().writeValueAsString(ErrorResponse.ERROR_1017),
                response.readEntity(String.class));
    }

    @Test
    public void shouldReturnStateOfMfaCodeVerifiedWhenUserHasAcceptedCurrentTermsAndConditions()
            throws IOException {
        String sessionId = RedisHelper.createSession();
        Scope scope = new Scope();
        scope.add(OIDCScopeValue.OPENID);
        scope.add(OIDCScopeValue.EMAIL);
        scope.add(OIDCScopeValue.PHONE);
        setUpTestWithoutClientConsent(sessionId, withScope(), SessionState.MFA_SMS_CODE_SENT);
        DynamoHelper.updateTermsAndConditions(EMAIL_ADDRESS, "1.0");
        ClientConsent clientConsent =
                new ClientConsent(
                        CLIENT_ID,
                        ValidScopes.getClaimsForListOfScopes(scope.toStringList()),
                        LocalDateTime.now().toString());
        DynamoHelper.updateConsent(EMAIL_ADDRESS, clientConsent);

        String code = RedisHelper.generateAndSaveMfaCode(EMAIL_ADDRESS, 900);
        VerifyCodeRequest codeRequest = new VerifyCodeRequest(NotificationType.MFA_SMS, code);

        Response response =
                RequestHelper.request(
                        FRONTEND_ROOT_RESOURCE_URL,
                        VERIFY_CODE_ENDPOINT,
                        codeRequest,
                        withHeaders(sessionId));

        assertEquals(200, response.getStatus());

        BaseAPIResponse codeResponse =
                objectMapper.readValue(response.readEntity(String.class), BaseAPIResponse.class);
        assertEquals(SessionState.MFA_CODE_VERIFIED, codeResponse.getSessionState());
    }

    @Test
    public void shouldReturnStateOfUpdatedTermsAndConditionsWhenUserHasNotAcceptedCurrentVersion()
            throws IOException {
        String sessionId = RedisHelper.createSession();
        Scope scope = new Scope();
        scope.add(OIDCScopeValue.OPENID);
        scope.add(OIDCScopeValue.EMAIL);
        scope.add(OIDCScopeValue.PHONE);
        setUpTestWithoutClientConsent(sessionId, scope, SessionState.MFA_SMS_CODE_SENT);

        DynamoHelper.updateTermsAndConditions(EMAIL_ADDRESS, "0.1");

        String code = RedisHelper.generateAndSaveMfaCode(EMAIL_ADDRESS, 900);
        VerifyCodeRequest codeRequest = new VerifyCodeRequest(NotificationType.MFA_SMS, code);

        Response response =
                RequestHelper.request(
                        FRONTEND_ROOT_RESOURCE_URL,
                        VERIFY_CODE_ENDPOINT,
                        codeRequest,
                        withHeaders(sessionId));

        assertEquals(200, response.getStatus());

        BaseAPIResponse codeResponse =
                objectMapper.readValue(response.readEntity(String.class), BaseAPIResponse.class);
        assertEquals(SessionState.UPDATED_TERMS_AND_CONDITIONS, codeResponse.getSessionState());
    }

    @Test
    public void shouldReturn400IfStateTransitionIsInvalid_SMS() throws IOException {
        String sessionId = RedisHelper.createSession();
        setUpTestWithoutSignUp(sessionId, withScope(), SessionState.NEW);

        String code = RedisHelper.generateAndSaveEmailCode(EMAIL_ADDRESS, 900);
        VerifyCodeRequest codeRequest = new VerifyCodeRequest(NotificationType.MFA_SMS, code);

        Response response =
                RequestHelper.request(
                        FRONTEND_ROOT_RESOURCE_URL,
                        VERIFY_CODE_ENDPOINT,
                        codeRequest,
                        withHeaders(sessionId));

        assertEquals(400, response.getStatus());
        assertEquals(
                new ObjectMapper().writeValueAsString(ErrorResponse.ERROR_1017),
                response.readEntity(String.class));
    }

    private void setUpTestWithoutSignUp(String sessionId, Scope scope, SessionState sessionState) {
        RedisHelper.addEmailToSession(sessionId, EMAIL_ADDRESS);
        RedisHelper.setSessionState(sessionId, sessionState);
        AuthenticationRequest authRequest =
                new AuthenticationRequest.Builder(
                                ResponseType.CODE,
                                scope,
                                new ClientID(CLIENT_ID),
                                URI.create(REDIRECT_URI))
                        .nonce(new Nonce())
                        .state(new State())
                        .build();
        RedisHelper.createClientSession(CLIENT_SESSION_ID, authRequest.toParameters());
        DynamoHelper.registerClient(
                CLIENT_ID,
                "test-client",
                singletonList("redirect-url"),
                singletonList(EMAIL_ADDRESS),
                List.of("openid", "email", "phone"),
                "public-key",
                singletonList("http://localhost/post-redirect-logout"),
                String.valueOf(ServiceType.MANDATORY),
                "https://test.com",
                "public");
    }

    private void setUpTestWithoutClientConsent(
            String sessionId, Scope scope, SessionState sessionState) {
        setUpTestWithoutSignUp(sessionId, scope, sessionState);
        DynamoHelper.signUp(EMAIL_ADDRESS, "password");
    }

    private Scope withScope() {
        Scope scope = new Scope();
        scope.add(OIDCScopeValue.OPENID);
        scope.add(OIDCScopeValue.EMAIL);
        return scope;
    }

    private MultivaluedMap<String, Object> withHeaders(String sessionId) {
        MultivaluedMap<String, Object> headers = new MultivaluedHashMap<>();
        headers.add("Session-Id", sessionId);
        headers.add("X-API-Key", FRONTEND_API_KEY);
        headers.add("Client-Session-Id", CLIENT_SESSION_ID);
        return headers;
    }
}
