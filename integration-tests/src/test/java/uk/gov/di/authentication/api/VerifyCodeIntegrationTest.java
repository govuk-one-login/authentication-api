package uk.gov.di.authentication.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.helpers.DynamoHelper;
import uk.gov.di.authentication.helpers.RedisHelper;
import uk.gov.di.authentication.helpers.RequestHelper;
import uk.gov.di.entity.BaseAPIResponse;
import uk.gov.di.entity.ErrorResponse;
import uk.gov.di.entity.NotificationType;
import uk.gov.di.entity.SessionState;
import uk.gov.di.entity.VerifyCodeRequest;

import java.io.IOException;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class VerifyCodeIntegrationTest extends IntegrationTestEndpoints {

    private static final String VERIFY_CODE_ENDPOINT = "/verify-code";
    private static final String EMAIL_ADDRESS = "test@test.com";
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    public void shouldCallVerifyCodeEndpointToVerifyEmailCodeAndReturn200() throws IOException {
        String sessionId = RedisHelper.createSession();
        RedisHelper.setSessionState(sessionId, SessionState.VERIFY_EMAIL_CODE_SENT);
        RedisHelper.addEmailToSession(sessionId, EMAIL_ADDRESS);

        String code = RedisHelper.generateAndSaveEmailCode(EMAIL_ADDRESS, 900);
        VerifyCodeRequest codeRequest = new VerifyCodeRequest(NotificationType.VERIFY_EMAIL, code);

        Response response =
                RequestHelper.requestWithSession(VERIFY_CODE_ENDPOINT, codeRequest, sessionId);

        assertEquals(200, response.getStatus());
    }

    @Test
    public void shouldCallVerifyCodeEndpointAndReturn200WitUpdatedStateWhenEmailCodeHasExpired()
            throws IOException, InterruptedException {
        String sessionId = RedisHelper.createSession();
        RedisHelper.setSessionState(sessionId, SessionState.VERIFY_EMAIL_CODE_SENT);
        RedisHelper.addEmailToSession(sessionId, EMAIL_ADDRESS);

        String code = RedisHelper.generateAndSaveEmailCode(EMAIL_ADDRESS, 2);
        VerifyCodeRequest codeRequest = new VerifyCodeRequest(NotificationType.VERIFY_EMAIL, code);

        TimeUnit.SECONDS.sleep(3);

        Response response =
                RequestHelper.requestWithSession(VERIFY_CODE_ENDPOINT, codeRequest, sessionId);

        assertEquals(200, response.getStatus());
        BaseAPIResponse codeResponse =
                objectMapper.readValue(response.readEntity(String.class), BaseAPIResponse.class);
        assertEquals(SessionState.EMAIL_CODE_NOT_VALID, codeResponse.getSessionState());
    }

    @Test
    public void shouldReturn200WithNewStateWhenUserTriesEmailCodeThatTheyHaveAlreadyUsed()
            throws IOException {
        String sessionId = RedisHelper.createSession();
        RedisHelper.setSessionState(sessionId, SessionState.VERIFY_EMAIL_CODE_SENT);
        RedisHelper.addEmailToSession(sessionId, EMAIL_ADDRESS);
        String code = RedisHelper.generateAndSaveEmailCode(EMAIL_ADDRESS, 900);
        VerifyCodeRequest codeRequest = new VerifyCodeRequest(NotificationType.VERIFY_EMAIL, code);

        Response response =
                RequestHelper.requestWithSession(VERIFY_CODE_ENDPOINT, codeRequest, sessionId);

        assertEquals(200, response.getStatus());

        Response response2 =
                RequestHelper.requestWithSession(VERIFY_CODE_ENDPOINT, codeRequest, sessionId);

        assertEquals(200, response2.getStatus());

        BaseAPIResponse codeResponse =
                objectMapper.readValue(response2.readEntity(String.class), BaseAPIResponse.class);
        assertEquals(SessionState.EMAIL_CODE_NOT_VALID, codeResponse.getSessionState());
    }

    @Test
    public void shouldCallVerifyCodeEndpointToVerifyPhoneCodeAndReturn200() throws IOException {
        String sessionId = RedisHelper.createSession();
        RedisHelper.addEmailToSession(sessionId, EMAIL_ADDRESS);
        RedisHelper.setSessionState(sessionId, SessionState.VERIFY_PHONE_NUMBER_CODE_SENT);

        String code = RedisHelper.generateAndSavePhoneNumberCode(EMAIL_ADDRESS, 900);
        VerifyCodeRequest codeRequest =
                new VerifyCodeRequest(NotificationType.VERIFY_PHONE_NUMBER, code);
        DynamoHelper.signUp(EMAIL_ADDRESS, "password");

        Response response =
                RequestHelper.requestWithSession(VERIFY_CODE_ENDPOINT, codeRequest, sessionId);

        assertEquals(200, response.getStatus());
    }

    @Test
    public void
            shouldCallVerifyCodeEndpointAndReturn200WitUpdatedStateWhenPhoneNumberCodeHasExpired()
                    throws IOException, InterruptedException {
        String sessionId = RedisHelper.createSession();
        RedisHelper.addEmailToSession(sessionId, EMAIL_ADDRESS);
        RedisHelper.setSessionState(sessionId, SessionState.VERIFY_PHONE_NUMBER_CODE_SENT);

        String code = RedisHelper.generateAndSavePhoneNumberCode(EMAIL_ADDRESS, 2);
        VerifyCodeRequest codeRequest =
                new VerifyCodeRequest(NotificationType.VERIFY_PHONE_NUMBER, code);

        TimeUnit.SECONDS.sleep(3);

        Response response =
                RequestHelper.requestWithSession(VERIFY_CODE_ENDPOINT, codeRequest, sessionId);

        assertEquals(200, response.getStatus());

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

        VerifyCodeRequest codeRequest =
                new VerifyCodeRequest(NotificationType.VERIFY_PHONE_NUMBER, "123456");

        Response response =
                RequestHelper.requestWithSession(VERIFY_CODE_ENDPOINT, codeRequest, sessionId);

        assertEquals(200, response.getStatus());

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

        VerifyCodeRequest codeRequest =
                new VerifyCodeRequest(NotificationType.VERIFY_EMAIL, "123456");

        Response response =
                RequestHelper.requestWithSession(VERIFY_CODE_ENDPOINT, codeRequest, sessionId);

        assertEquals(200, response.getStatus());

        BaseAPIResponse codeResponse =
                objectMapper.readValue(response.readEntity(String.class), BaseAPIResponse.class);
        assertEquals(SessionState.EMAIL_CODE_MAX_RETRIES_REACHED, codeResponse.getSessionState());
    }

    @Test
    public void shouldReturn400IfStateTransitionIsInvalid() throws IOException {
        String sessionId = RedisHelper.createSession();
        RedisHelper.setSessionState(sessionId, SessionState.NEW);
        RedisHelper.addEmailToSession(sessionId, EMAIL_ADDRESS);

        String code = RedisHelper.generateAndSaveEmailCode(EMAIL_ADDRESS, 900);
        VerifyCodeRequest codeRequest = new VerifyCodeRequest(NotificationType.VERIFY_EMAIL, code);

        Response response =
                RequestHelper.requestWithSession(VERIFY_CODE_ENDPOINT, codeRequest, sessionId);

        assertEquals(400, response.getStatus());
        assertEquals(
                new ObjectMapper().writeValueAsString(ErrorResponse.ERROR_1019),
                response.readEntity(String.class));
    }

    @Test
    public void shouldReturn400IfStateTransitionIsInvalid_PhoneNumber() throws IOException {
        String sessionId = RedisHelper.createSession();
        RedisHelper.setSessionState(sessionId, SessionState.NEW);
        RedisHelper.addEmailToSession(sessionId, EMAIL_ADDRESS);

        String code = RedisHelper.generateAndSavePhoneNumberCode(EMAIL_ADDRESS, 900);
        VerifyCodeRequest codeRequest =
                new VerifyCodeRequest(NotificationType.VERIFY_PHONE_NUMBER, code);
        DynamoHelper.signUp(EMAIL_ADDRESS, "password");

        Response response =
                RequestHelper.requestWithSession(VERIFY_CODE_ENDPOINT, codeRequest, sessionId);

        assertEquals(400, response.getStatus());
        assertEquals(
                new ObjectMapper().writeValueAsString(ErrorResponse.ERROR_1019),
                response.readEntity(String.class));
    }

    @Test
    public void shouldCallVerifyCodeEndpointToVerifyMfaCodeAndReturn200() throws IOException {
        String sessionId = RedisHelper.createSession();
        RedisHelper.addEmailToSession(sessionId, EMAIL_ADDRESS);

        String code = RedisHelper.generateAndSaveEmailCode(EMAIL_ADDRESS, 900);
        VerifyCodeRequest codeRequest = new VerifyCodeRequest(NotificationType.MFA_SMS, code);

        Response response =
                RequestHelper.requestWithSession(VERIFY_CODE_ENDPOINT, codeRequest, sessionId);

        assertEquals(200, response.getStatus());
    }
}
