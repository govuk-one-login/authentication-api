package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.shared.entity.IDReverificationState;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.IDReverificationStateService;

import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_REVERIFY_UNSUCCESSFUL_AUTHORISATION_RECEIVED;
import static uk.gov.di.authentication.frontendapi.helpers.ApiGatewayProxyRequestHelper.apiRequestEventWithHeadersAndBody;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.CLIENT_SESSION_ID;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.ENCODED_DEVICE_DETAILS;
import static uk.gov.di.authentication.shared.helpers.TxmaAuditHelper.TXMA_AUDIT_ENCODED_HEADER;

public class IDReverificationStateHandlerTest {
    public static final String AUTHENTICATION_STATE = "state";
    public static final String ORCHESTRATION_REDIRECT_URL = "redirect-url";
    private final Context context = mock(Context.class);
    private final AuditService auditService = mock(AuditService.class);
    private final IDReverificationStateService idReverificationStateService =
            mock(IDReverificationStateService.class);
    private IDReverificationStateHandler handler;

    @BeforeEach
    void setUp() {
        handler = new IDReverificationStateHandler(auditService, idReverificationStateService);
        when(context.getAwsRequestId()).thenReturn("aws-request-id");
    }

    @Test
    void shouldReturn200AndTheCorrectRedirectUrl() throws Json.JsonException {
        givenThereIsAStoredStateEntry();
        var response = handler.handleRequest(generateRequest(AUTHENTICATION_STATE), context);

        assertEquals(200, response.getStatusCode());
        assertEquals(
                String.format("{\"orchestrationRedirectUrl\":\"%s\"}", ORCHESTRATION_REDIRECT_URL),
                response.getBody());
    }

    @Test
    void shouldReturn404WhenNoMatchingState() throws Json.JsonException {
        givenThereIsNoStoredStateEntry();
        var response = handler.handleRequest(generateRequest(AUTHENTICATION_STATE), context);
        assertEquals(404, response.getStatusCode());
    }

    @Test
    void shouldEmitTheCorrectAuditEvent() throws Json.JsonException {
        givenThereIsAStoredStateEntry();
        handler.handleRequest(generateRequest(AUTHENTICATION_STATE), context);

        verify(auditService)
                .submitAuditEvent(
                        AUTH_REVERIFY_UNSUCCESSFUL_AUTHORISATION_RECEIVED,
                        AuditContext.emptyAuditContext()
                                .withClientSessionId(CLIENT_SESSION_ID)
                                .withTxmaAuditEncoded(Optional.of(ENCODED_DEVICE_DETAILS)));
    }

    private static APIGatewayProxyRequestEvent generateRequest(String authenticationState) {
        return apiRequestEventWithHeadersAndBody(
                Map.of(TXMA_AUDIT_ENCODED_HEADER, ENCODED_DEVICE_DETAILS),
                String.format("{\"authenticationState\": \"%s\"}", authenticationState));
    }

    private void givenThereIsAStoredStateEntry() {
        var idReverificationState =
                new IDReverificationState()
                        .withClientSessionId(CLIENT_SESSION_ID)
                        .withOrchestrationRedirectUrl(ORCHESTRATION_REDIRECT_URL);
        when(idReverificationStateService.get(any()))
                .thenReturn(Optional.of(idReverificationState));
    }

    private void givenThereIsNoStoredStateEntry() {
        when(idReverificationStateService.get(any())).thenReturn(Optional.empty());
    }
}
