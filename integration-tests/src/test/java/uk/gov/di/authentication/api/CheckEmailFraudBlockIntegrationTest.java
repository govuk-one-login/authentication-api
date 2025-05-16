package uk.gov.di.authentication.api;

import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.frontendapi.entity.CheckEmailFraudBlockResponse;
import uk.gov.di.authentication.frontendapi.lambda.CheckEmailFraudBlockHandler;
import uk.gov.di.authentication.shared.entity.EmailCheckResultStatus;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.DynamoEmailCheckResultService;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;
import uk.gov.di.authentication.sharedtest.extensions.AuthSessionExtension;
import uk.gov.di.authentication.sharedtest.extensions.EmailCheckResultExtension;

import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

public class CheckEmailFraudBlockIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    private static final String EMAIL = "joe.bloggs@digital.cabinet-office.gov.uk";
    public static final String CLIENT_SESSION_ID = "some-client-session-id";
    private static final String INTERNAl_SECTOR_URI = "https://test.account.gov.uk";
    private static final String INTERNAl_SECTOR_HOST = "test.account.gov.uk";
    private static final Subject SUBJECT = new Subject();

    DynamoEmailCheckResultService dynamoEmailCheckResultService =
            new DynamoEmailCheckResultService(TEST_CONFIGURATION_SERVICE);

    @RegisterExtension
    protected static final EmailCheckResultExtension emailCheckResultExtension =
            new EmailCheckResultExtension();

    @RegisterExtension
    protected static final AuthSessionExtension authSessionExtension = new AuthSessionExtension();

    @BeforeEach
    void setup() {
        handler =
                new CheckEmailFraudBlockHandler(
                        TXMA_ENABLED_CONFIGURATION_SERVICE, redisConnectionService);
        txmaAuditQueue.clear();
    }

    @Test
    void shouldReturnCorrectStatusBasedOnDbResult() throws Json.JsonException {
        userStore.signUp(EMAIL, "password-1", SUBJECT);
        var sessionId = redis.createSession();
        authSessionExtension.addSession(sessionId);
        dynamoEmailCheckResultService.saveEmailCheckResult(
                EMAIL, EmailCheckResultStatus.ALLOW, unixTimePlusNDays(), "test-reference");
        Map<String, String> headers = new HashMap<>();
        headers.put("Session-Id", sessionId);
        headers.put("X-API-Key", FRONTEND_API_KEY);
        headers.put("Client-Session-Id", CLIENT_SESSION_ID);
        var response =
                makeRequest(Optional.of(format("{ \"email\": \"%s\"}", EMAIL)), headers, Map.of());

        assertThat(response, hasStatus(200));
        assertThat(
                response,
                hasJsonBody(
                        new CheckEmailFraudBlockResponse(
                                EMAIL, EmailCheckResultStatus.ALLOW.getValue())));
    }

    private long unixTimePlusNDays() {
        return NowHelper.nowPlus(1, ChronoUnit.DAYS).toInstant().getEpochSecond();
    }
}
