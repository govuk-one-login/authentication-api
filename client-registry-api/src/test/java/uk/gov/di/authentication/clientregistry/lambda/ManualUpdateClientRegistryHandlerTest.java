package uk.gov.di.authentication.clientregistry.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.clientregistry.services.ManualUpdateClientRegistryValidationService;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.entity.ClientType;
import uk.gov.di.orchestration.shared.entity.ManualUpdateClientRegistryRequest;
import uk.gov.di.orchestration.shared.services.AuditService;
import uk.gov.di.orchestration.shared.services.ClientService;
import uk.gov.di.orchestration.sharedtest.logging.CaptureLoggingExtension;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static java.lang.String.format;
import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.not;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.clientregistry.services.ManualUpdateClientRegistryValidationService.INVALID_RATE_LIMIT;
import static uk.gov.di.orchestration.sharedtest.logging.LogEventMatcher.withMessageContaining;

class ManualUpdateClientRegistryHandlerTest {

    private static final String CLIENT_ID = "client-id";
    private static final String VALID_RATE_LIMIT = "1";
    private static final String RESULT_KEY = "result";
    private static final String MESSAGE_KEY = "message";
    private static final String RESULT_ERROR = "error";
    private static final String RESULT_SUCCESS = "success";

    private final Context context = mock(Context.class);
    private final ClientService clientService = mock(ClientService.class);
    private final ManualUpdateClientRegistryValidationService clientValidationService =
            mock(ManualUpdateClientRegistryValidationService.class);
    private final AuditService auditService = mock(AuditService.class);
    private ManualUpdateClientRegistryHandler handler;

    @BeforeEach
    void setUp() {
        handler =
                new ManualUpdateClientRegistryHandler(
                        clientService, clientValidationService, auditService);
    }

    @RegisterExtension
    public final CaptureLoggingExtension logging =
            new CaptureLoggingExtension(ManualUpdateClientRegistryHandler.class);

    @AfterEach
    void afterEach() {
        assertThat(logging.events(), not(hasItem(withMessageContaining(CLIENT_ID))));
        verifyNoMoreInteractions(auditService);
    }

    @Test
    void shouldReturnResultSuccessForAValidRequest() {
        when(clientService.isValidClient(CLIENT_ID)).thenReturn(true);
        when(clientValidationService.validateManualUpdateClientRegistryRequest(
                        any(ManualUpdateClientRegistryRequest.class)))
                .thenReturn(Optional.empty());
        when(clientService.manualUpdateClient(
                        eq(CLIENT_ID), any(ManualUpdateClientRegistryRequest.class)))
                .thenReturn(createClientRegistry());

        String event =
                format(
                        "{\"client_id\": \"%s\", \"rate_limit\": \"%s\"}",
                        CLIENT_ID, VALID_RATE_LIMIT);
        var result = makeHandlerRequest(event);

        assertThat(result.get(RESULT_KEY), equalTo(RESULT_SUCCESS));
        assertThat(
                result.get(MESSAGE_KEY),
                equalTo("Successfully update client with values: ClientId=client-id, RateLimit=1"));
    }

    @Test
    void shouldReturn400WhenRequestContainsNoParameters() {
        String event = "";
        var result = makeHandlerRequest(event);

        assertThat(result.get(RESULT_KEY), equalTo(RESULT_ERROR));
        assertThat(result.get(MESSAGE_KEY), equalTo("No client config provided"));
    }

    @Test
    void shouldReturnResultErrorWhenRequestIsMissingClientID() {
        String event = format("{\"rate_limit\": \"%s\"}", VALID_RATE_LIMIT);
        var result = makeHandlerRequest(event);

        assertThat(result.get(RESULT_KEY), equalTo(RESULT_ERROR));
        assertThat(
                result.get(MESSAGE_KEY),
                equalTo(
                        "Invalid Client registration request. Missing parameters or incorrect type from request"));
    }

    @Test
    void shouldReturnResultErrorWhenClientIdIsInvalid() {
        when(clientService.isValidClient(CLIENT_ID)).thenReturn(false);

        String event =
                format(
                        "{\"client_id\": \"%s\", \"rate_limit\": \"%s\"}",
                        CLIENT_ID, VALID_RATE_LIMIT);
        var result = makeHandlerRequest(event);

        assertThat(result.get(RESULT_KEY), equalTo(RESULT_ERROR));
        assertThat(result.get(MESSAGE_KEY), equalTo("Invalid client id"));
    }

    @Test
    void shouldReturnResultErrorWhenRequestFailsValidation() {
        when(clientService.isValidClient(CLIENT_ID)).thenReturn(true);
        when(clientValidationService.validateManualUpdateClientRegistryRequest(
                        any(ManualUpdateClientRegistryRequest.class)))
                .thenReturn(Optional.of(INVALID_RATE_LIMIT));
        when(clientService.manualUpdateClient(
                        eq(CLIENT_ID), any(ManualUpdateClientRegistryRequest.class)))
                .thenReturn(createClientRegistry());

        String event = format("{\"client_id\": \"%s\", \"rate_limit\": \"%s\"}", CLIENT_ID, "-1");
        var result = makeHandlerRequest(event);

        assertThat(result.get(RESULT_KEY), equalTo(RESULT_ERROR));
        assertThat(
                result.get(MESSAGE_KEY),
                equalTo(
                        "Failed validation. ErrorCode: invalid_rate_limit. ErrorDescription: Invalid client rate limit"));
    }

    private ClientRegistry createClientRegistry() {
        return new ClientRegistry()
                .withClientID(CLIENT_ID)
                .withPublicKey("public-key")
                .withSubjectType("Public")
                .withRedirectUrls(singletonList("http://localhost/redirect"))
                .withContacts(singletonList("contant-name"))
                .withPostLogoutRedirectUrls(singletonList("localhost/logout"))
                .withClientType(ClientType.WEB.getValue())
                .withClaims(List.of("claim"));
    }

    private Map<String, String> makeHandlerRequest(String event) {
        return handler.handleRequest(event, context);
    }
}
