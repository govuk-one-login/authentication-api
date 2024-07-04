package uk.gov.di.authentication.api;

import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.frontendapi.entity.CheckEmailFraudBlockResponse;
import uk.gov.di.authentication.frontendapi.lambda.CheckEmailFraudBlockHandler;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.EmailCheckResultStatus;
import uk.gov.di.authentication.shared.entity.VectorOfTrust;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.DynamoEmailCheckResultService;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;
import uk.gov.di.authentication.sharedtest.extensions.EmailCheckResultExtension;

import java.net.URI;
import java.time.LocalDateTime;
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
        dynamoEmailCheckResultService.saveEmailCheckResult(
                EMAIL, EmailCheckResultStatus.ALLOW, unixTimePlusNDays(), "test-reference");
        redis.addEmailToSession(sessionId, EMAIL);
        redis.createClientSession(CLIENT_SESSION_ID, createClientSession());
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

    private ClientSession createClientSession() {
        var authRequestBuilder =
                new AuthenticationRequest.Builder(
                                ResponseType.CODE,
                                new Scope(OIDCScopeValue.OPENID),
                                new ClientID("test-client-id"),
                                URI.create("http://localhost/redirect"))
                        .state(new State())
                        .nonce(new Nonce());
        return new ClientSession(
                authRequestBuilder.build().toParameters(),
                LocalDateTime.now(),
                VectorOfTrust.getDefaults(),
                "test-client-name");
    }

    private long unixTimePlusNDays() {
        return NowHelper.nowPlus(1, ChronoUnit.DAYS).toInstant().getEpochSecond();
    }
}
