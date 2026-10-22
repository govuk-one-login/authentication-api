package uk.gov.di.authentication.accountdata.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import uk.gov.di.authentication.accountdata.entity.password.VerifyPasswordResponse;
import uk.gov.di.authentication.accountdata.entity.password.failurereasons.VerifyPasswordFailureReason;
import uk.gov.di.authentication.accountdata.services.ConfigurationService;
import uk.gov.di.authentication.accountdata.services.PasswordService;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.SerializationService;

import java.util.HashMap;
import java.util.Map;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.accountdata.helpers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.accountdata.helpers.APIGatewayProxyResponseEventMatcher.hasStatus;
import static uk.gov.di.authentication.accountdata.helpers.CommonTestVariables.ANOTHER_PUBLIC_SUBJECT_ID;
import static uk.gov.di.authentication.accountdata.helpers.CommonTestVariables.IP_ADDRESS;
import static uk.gov.di.authentication.accountdata.helpers.CommonTestVariables.PASSWORD;
import static uk.gov.di.authentication.accountdata.helpers.CommonTestVariables.PUBLIC_SUBJECT_ID;
import static uk.gov.di.authentication.accountdata.helpers.RequestHelper.contextWithSourceIp;

public class VerifyPasswordHandlerTest {

    private final Context context = mock(Context.class);
    private final Json objectMapper = SerializationService.getInstance();
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final PasswordService passwordService = mock(PasswordService.class);

    private VerifyPasswordHandler handler;

    @BeforeEach
    void setUp() {
        handler = new VerifyPasswordHandler(configurationService, passwordService);
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldReturn200WhenVerifyPasswordSuccessful(boolean passwordVerified)
            throws Json.JsonException {
        var pathParams = Map.of("publicSubjectId", PUBLIC_SUBJECT_ID);
        var requestBody = new HashMap<>();
        requestBody.put("password", PASSWORD);
        var authorizerParams =
                Map.<String, Object>of("principalId", PUBLIC_SUBJECT_ID, "scope", "account-delete");
        when(passwordService.verifyPassword(PUBLIC_SUBJECT_ID, PASSWORD))
                .thenReturn(Result.success(passwordVerified));
        var verifyPasswordRequest =
                verifyPasswordRequest(
                        pathParams, authorizerParams, objectMapper.writeValueAsString(requestBody));

        var result = handler.handleRequest(verifyPasswordRequest, context);

        assertThat(result, hasStatus(200));
        assertThat(result, hasJsonBody(new VerifyPasswordResponse(passwordVerified)));
    }

    @Test
    void shouldReturn400WhenInvalidRequestBody() throws Json.JsonException {
        var pathParams = Map.of("publicSubjectId", PUBLIC_SUBJECT_ID);
        var invalidRequestBody = new HashMap<>();
        invalidRequestBody.put("invalidProperty", "invalid");
        var authorizerParams =
                Map.<String, Object>of("principalId", PUBLIC_SUBJECT_ID, "scope", "account-delete");
        var verifyPasswordRequest =
                verifyPasswordRequest(
                        pathParams,
                        authorizerParams,
                        objectMapper.writeValueAsString(invalidRequestBody));

        var result = handler.handleRequest(verifyPasswordRequest, context);

        assertThat(result, hasStatus(400));
    }

    @Test
    void shouldReturn400WhenPublicSubjectIdMissing() throws Json.JsonException {
        var pathParams = Map.of("", "");
        var requestBody = new HashMap<>();
        requestBody.put("password", "some-password");
        var authorizerParams =
                Map.<String, Object>of("principalId", PUBLIC_SUBJECT_ID, "scope", "account-delete");
        var verifyPasswordRequest =
                verifyPasswordRequest(
                        pathParams, authorizerParams, objectMapper.writeValueAsString(requestBody));

        var result = handler.handleRequest(verifyPasswordRequest, context);

        assertThat(result, hasStatus(400));
    }

    @Test
    void shouldReturn403WhenPublicSubjectIdDoesNotMatchTheOneInAuthorizerParams()
            throws Json.JsonException {
        var pathParams = Map.of("publicSubjectId", ANOTHER_PUBLIC_SUBJECT_ID);
        var requestBody = new HashMap<>();
        requestBody.put("password", "some-password");
        var authorizerParams =
                Map.<String, Object>of("principalId", PUBLIC_SUBJECT_ID, "scope", "account-delete");
        var verifyPasswordRequest =
                verifyPasswordRequest(
                        pathParams, authorizerParams, objectMapper.writeValueAsString(requestBody));

        var result = handler.handleRequest(verifyPasswordRequest, context);

        assertThat(result, hasStatus(403));
    }

    @Test
    void shouldReturn403WhenScopeIsNotAccountDelete() throws Json.JsonException {
        var pathParams = Map.of("publicSubjectId", ANOTHER_PUBLIC_SUBJECT_ID);
        var requestBody = new HashMap<>();
        requestBody.put("password", "some-password");
        var authorizerParams =
                Map.<String, Object>of("principalId", PUBLIC_SUBJECT_ID, "scope", "account-delete");
        var verifyPasswordRequest =
                verifyPasswordRequest(
                        pathParams, authorizerParams, objectMapper.writeValueAsString(requestBody));

        var result = handler.handleRequest(verifyPasswordRequest, context);

        assertThat(result, hasStatus(403));
    }

    @Test
    void shouldReturn404WhenUserNotFoundDuringPasswordVerification() throws Json.JsonException {
        var pathParams = Map.of("publicSubjectId", PUBLIC_SUBJECT_ID);
        var requestBody = new HashMap<>();
        requestBody.put("password", PASSWORD);
        var authorizerParams =
                Map.<String, Object>of("principalId", PUBLIC_SUBJECT_ID, "scope", "account-delete");
        when(passwordService.verifyPassword(PUBLIC_SUBJECT_ID, PASSWORD))
                .thenReturn(Result.failure(VerifyPasswordFailureReason.USER_NOT_FOUND));
        var verifyPasswordRequest =
                verifyPasswordRequest(
                        pathParams, authorizerParams, objectMapper.writeValueAsString(requestBody));

        var result = handler.handleRequest(verifyPasswordRequest, context);

        assertThat(result, hasStatus(404));
    }

    private APIGatewayProxyRequestEvent verifyPasswordRequest(
            Map<String, String> pathParams, Map<String, Object> authorizerParams, String body) {
        var context = contextWithSourceIp(IP_ADDRESS);
        context.setAuthorizer(authorizerParams);
        return new APIGatewayProxyRequestEvent()
                .withBody(body)
                .withRequestContext(context)
                .withPathParameters(pathParams);
    }
}
