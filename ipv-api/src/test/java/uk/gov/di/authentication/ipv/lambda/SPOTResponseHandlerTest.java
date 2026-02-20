package uk.gov.di.authentication.ipv.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.SQSEvent;
import com.nimbusds.oauth2.sdk.id.ClientID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.orchestration.audit.TxmaAuditUser;
import uk.gov.di.orchestration.shared.entity.OrchIdentityCredentials;
import uk.gov.di.orchestration.shared.services.AuditService;
import uk.gov.di.orchestration.shared.services.CloudwatchMetricsService;
import uk.gov.di.orchestration.shared.services.DynamoIdentityService;

import static java.lang.String.format;
import static java.util.Collections.singletonList;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.ipv.domain.IPVAuditableEvent.IPV_SUCCESSFUL_SPOT_RESPONSE_RECEIVED;
import static uk.gov.di.authentication.ipv.domain.IPVAuditableEvent.IPV_UNSUCCESSFUL_SPOT_RESPONSE_RECEIVED;

class SPOTResponseHandlerTest {

    private SPOTResponseHandler handler;
    private final Context context = mock(Context.class);
    private final DynamoIdentityService dynamoIdentityService = mock(DynamoIdentityService.class);
    private final AuditService auditService = mock(AuditService.class);
    private final CloudwatchMetricsService cloudwatchMetricsService =
            mock(CloudwatchMetricsService.class);

    private static final String REQUEST_ID = "request-id";
    private static final String SESSION_ID = "a-session-id";
    private static final String PERSISTENT_SESSION_ID = "a-persistent-id";
    private static final String CLIENT_SESSION_ID = "known-client-session-id";

    private static final ClientID CLIENT_ID = new ClientID();
    private static final TxmaAuditUser USER =
            TxmaAuditUser.user()
                    .withGovukSigninJourneyId(CLIENT_SESSION_ID)
                    .withSessionId(SESSION_ID)
                    .withPersistentSessionId(PERSISTENT_SESSION_ID);

    @BeforeEach
    void setup() {
        handler =
                new SPOTResponseHandler(
                        dynamoIdentityService, auditService, cloudwatchMetricsService);

        when(context.getAwsRequestId()).thenReturn(REQUEST_ID);
    }

    @Test
    void shouldWriteToDynamoForSuccessfulSPOTResponse() {
        when(dynamoIdentityService.addCoreIdentityJWT(any(), any(), any()))
                .thenReturn(new OrchIdentityCredentials().withSpotQueuedAtMs(123456789L));
        var json =
                format(
                        "{\"sub\":\"urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6\",\"status\":\"ACCEPTED\","
                                + "\"claims\":{\"http://something/v1/verifiableIdentityJWT\":\"random-searalized-credential\"}, "
                                + "\"log_ids\":{\"session_id\":\"%s\",\"persistent_session_id\":\"%s\",\"request_id\":\"%s\",\"client_id\":\"%s\",\"client_session_id\":\"%s\"}}",
                        SESSION_ID,
                        PERSISTENT_SESSION_ID,
                        REQUEST_ID,
                        CLIENT_ID,
                        CLIENT_SESSION_ID);

        handler.handleRequest(generateSQSEvent(json), context);

        verify(dynamoIdentityService)
                .addCoreIdentityJWT(
                        CLIENT_SESSION_ID,
                        "urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
                        "random-searalized-credential");

        verify(auditService)
                .submitAuditEvent(
                        IPV_SUCCESSFUL_SPOT_RESPONSE_RECEIVED, CLIENT_ID.getValue(), USER);
        verify(cloudwatchMetricsService)
                .putEmbeddedValue(eq("SpotLatencyMs"), any(Double.class), anyMap());
    }

    @Test
    void itGracefullyHandlesCloudwatchMetricThrowingAnError() {
        when(dynamoIdentityService.addCoreIdentityJWT(any(), any(), any()))
                .thenReturn(new OrchIdentityCredentials().withSpotQueuedAtMs(123456789L));
        doThrow(RuntimeException.class)
                .when(cloudwatchMetricsService)
                .putEmbeddedValue(anyString(), any(Double.class), anyMap());
        var json =
                format(
                        "{\"sub\":\"urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6\",\"status\":\"ACCEPTED\","
                                + "\"claims\":{\"http://something/v1/verifiableIdentityJWT\":\"random-searalized-credential\"}, "
                                + "\"log_ids\":{\"session_id\":\"%s\",\"persistent_session_id\":\"%s\",\"request_id\":\"%s\",\"client_id\":\"%s\",\"client_session_id\":\"%s\"}}",
                        SESSION_ID,
                        PERSISTENT_SESSION_ID,
                        REQUEST_ID,
                        CLIENT_ID,
                        CLIENT_SESSION_ID);

        assertDoesNotThrow(() -> handler.handleRequest(generateSQSEvent(json), context));

        verify(dynamoIdentityService)
                .addCoreIdentityJWT(
                        CLIENT_SESSION_ID,
                        "urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
                        "random-searalized-credential");

        verify(auditService)
                .submitAuditEvent(
                        IPV_SUCCESSFUL_SPOT_RESPONSE_RECEIVED, CLIENT_ID.getValue(), USER);
    }

    @Test
    void shouldNotWriteToDynamoWhenLambdaReceivedInvalidSPOTResponse() {
        handler.handleRequest(generateSQSEvent("invalid-payload"), context);

        verifyNoInteractions(dynamoIdentityService);

        verifyNoInteractions(auditService);
    }

    @Test
    void shouldDeleteIdentityCredentialWhenSPOTResponseStatusIsNotACCEPTED() {
        var json =
                format(
                        "{\"sub\":\"urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6\",\"status\":\"REJECTED\","
                                + "\"log_ids\":{\"session_id\":\"%s\",\"persistent_session_id\":\"%s\",\"request_id\":\"%s\",\"client_id\":\"%s\",\"client_session_id\":\"%s\"}}",
                        SESSION_ID,
                        PERSISTENT_SESSION_ID,
                        REQUEST_ID,
                        CLIENT_ID,
                        CLIENT_SESSION_ID);

        handler.handleRequest(generateSQSEvent(json), context);

        verify(dynamoIdentityService).deleteIdentityCredentials(CLIENT_SESSION_ID);

        verify(auditService)
                .submitAuditEvent(
                        IPV_UNSUCCESSFUL_SPOT_RESPONSE_RECEIVED, CLIENT_ID.getValue(), USER);
    }

    private SQSEvent generateSQSEvent(String messageBody) {
        SQSEvent.SQSMessage sqsMessage = new SQSEvent.SQSMessage();
        sqsMessage.setBody(messageBody);
        SQSEvent sqsEvent = new SQSEvent();
        sqsEvent.setRecords(singletonList(sqsMessage));
        return sqsEvent;
    }
}
