package uk.gov.di.authentication.clientregistry.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.clientregistry.entity.ClientRegistrationResponse;
import uk.gov.di.authentication.clientregistry.services.ClientConfigValidationService;
import uk.gov.di.orchestration.audit.TxmaAuditUser;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.entity.ClientType;
import uk.gov.di.orchestration.shared.entity.UpdateClientConfigRequest;
import uk.gov.di.orchestration.shared.serialization.Json;
import uk.gov.di.orchestration.shared.services.AuditService;
import uk.gov.di.orchestration.shared.services.ClientService;
import uk.gov.di.orchestration.shared.services.SerializationService;
import uk.gov.di.orchestration.sharedtest.logging.CaptureLoggingExtension;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static java.lang.String.format;
import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.clientregistry.domain.ClientRegistryAuditableEvent.UPDATE_CLIENT_REQUEST_ERROR;
import static uk.gov.di.authentication.clientregistry.domain.ClientRegistryAuditableEvent.UPDATE_CLIENT_REQUEST_RECEIVED;
import static uk.gov.di.authentication.clientregistry.services.ClientConfigValidationService.INVALID_PUBLIC_KEY;
import static uk.gov.di.authentication.clientregistry.services.ClientConfigValidationService.INVALID_SCOPE;
import static uk.gov.di.orchestration.shared.entity.ServiceType.MANDATORY;
import static uk.gov.di.orchestration.sharedtest.logging.LogEventMatcher.withMessageContaining;
import static uk.gov.di.orchestration.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasBody;
import static uk.gov.di.orchestration.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class UpdateClientConfigHandlerTest {

    private static final String CLIENT_ID = "client-id-1";
    private static final String CLIENT_NAME = "client-name-one";
    private static final List<String> SCOPES = singletonList("openid");
    private static final String SERVICE_TYPE = String.valueOf(MANDATORY);
    private static final Json objectMapper = SerializationService.getInstance();
    private static final TxmaAuditUser USER = TxmaAuditUser.user().withIpAddress("");

    private final Context context = mock(Context.class);
    private final ClientService clientService = mock(ClientService.class);
    private final ClientConfigValidationService clientValidationService =
            mock(ClientConfigValidationService.class);
    private final AuditService auditService = mock(AuditService.class);
    private UpdateClientConfigHandler handler;

    @BeforeEach
    void setUp() {
        when(context.getAwsRequestId()).thenReturn("request-id");
        handler =
                new UpdateClientConfigHandler(clientService, clientValidationService, auditService);
    }

    @RegisterExtension
    public final CaptureLoggingExtension logging =
            new CaptureLoggingExtension(UpdateClientConfigHandler.class);

    @AfterEach
    void afterEach() {
        assertThat(logging.events(), not(hasItem(withMessageContaining(CLIENT_ID, CLIENT_NAME))));
        verifyNoMoreInteractions(auditService);
    }

    @Test
    void shouldReturn200ForAValidRequest() throws Json.JsonException {
        when(clientService.isValidClient(CLIENT_ID)).thenReturn(true);
        when(clientValidationService.validateClientUpdateConfig(
                        any(UpdateClientConfigRequest.class)))
                .thenReturn(Optional.empty());
        when(clientService.updateSSEClient(eq(CLIENT_ID), any(UpdateClientConfigRequest.class)))
                .thenReturn(createClientRegistry());

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody(format("{\"client_name\": \"%s\"}", CLIENT_NAME));
        event.setPathParameters(Map.of("clientId", CLIENT_ID));
        APIGatewayProxyResponseEvent result = makeHandlerRequest(event);

        assertThat(result, hasStatus(200));
        ClientRegistrationResponse clientRegistrationResponse =
                objectMapper.readValue(result.getBody(), ClientRegistrationResponse.class);
        assertThat(clientRegistrationResponse.getClientId(), equalTo(CLIENT_ID));
        assertThat(clientRegistrationResponse.getClientName(), equalTo(CLIENT_NAME));
        assertThat(clientRegistrationResponse.getSubjectType(), equalTo("Public"));
        assertThat(clientRegistrationResponse.getTokenAuthMethod(), equalTo("private_key_jwt"));
        assertThat(clientRegistrationResponse.getScopes(), equalTo(SCOPES));
        assertThat(clientRegistrationResponse.getServiceType(), equalTo(SERVICE_TYPE));
        assertThat(clientRegistrationResponse.getJarValidationRequired(), equalTo(false));
        assertThat(clientRegistrationResponse.getClientType(), equalTo(ClientType.WEB.getValue()));
        assertThat(clientRegistrationResponse.getClaims(), equalTo(List.of("claim")));
    }

    @Test
    void shouldReturn400WhenRequestIsMissingClientID() {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody(format("{\"client_name\": \"%s\"}", CLIENT_NAME));
        APIGatewayProxyResponseEvent result = makeHandlerRequest(event);
        assertThat(result, hasStatus(400));
        assertThat(result, hasBody(OAuth2Error.INVALID_REQUEST.toJSONObject().toJSONString()));

        verify(auditService).submitAuditEvent(UPDATE_CLIENT_REQUEST_ERROR, "", USER);
    }

    @Test
    void shouldReturn400WhenRequestContainsNoParameters() {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody("");
        event.setPathParameters(Map.of("clientId", CLIENT_ID));
        APIGatewayProxyResponseEvent result = makeHandlerRequest(event);
        assertThat(result, hasStatus(400));
        assertThat(result, hasBody(OAuth2Error.INVALID_REQUEST.toJSONObject().toJSONString()));

        verify(auditService).submitAuditEvent(UPDATE_CLIENT_REQUEST_ERROR, "", USER);
    }

    @Test
    void shouldReturn401WhenClientIdIsInvalid() {
        when(clientService.isValidClient(CLIENT_ID)).thenReturn(false);

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setPathParameters(Map.of("clientId", CLIENT_ID));
        event.setBody(format("{\"client_name\": \"%s\"}", CLIENT_NAME));
        APIGatewayProxyResponseEvent result = makeHandlerRequest(event);
        assertThat(result, hasStatus(400));
        assertThat(result, hasBody(OAuth2Error.INVALID_CLIENT.toJSONObject().toJSONString()));

        verify(auditService).submitAuditEvent(UPDATE_CLIENT_REQUEST_ERROR, CLIENT_ID, USER);
    }

    @Test
    void shouldReturn400WhenRequestFailsValidation() {
        when(clientService.isValidClient(CLIENT_ID)).thenReturn(true);
        when(clientValidationService.validateClientUpdateConfig(
                        any(UpdateClientConfigRequest.class)))
                .thenReturn(Optional.of(INVALID_PUBLIC_KEY));

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody(
                format(
                        "{\"client_name\": \"%s\", \"public_key\": \"%s\"}",
                        CLIENT_NAME, "rubbush-public-keu"));
        event.setPathParameters(Map.of("clientId", CLIENT_ID));
        APIGatewayProxyResponseEvent result = makeHandlerRequest(event);

        assertThat(result, hasStatus(400));
        assertThat(result, hasBody(INVALID_PUBLIC_KEY.toJSONObject().toJSONString()));

        verify(auditService).submitAuditEvent(UPDATE_CLIENT_REQUEST_ERROR, CLIENT_ID, USER);
    }

    @Test
    void shouldReturn400WhenRequestHasInvalidScope() {
        when(clientService.isValidClient(CLIENT_ID)).thenReturn(true);
        when(clientValidationService.validateClientUpdateConfig(
                        any(UpdateClientConfigRequest.class)))
                .thenReturn(Optional.of(INVALID_SCOPE));

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody(format("{\"client_name\": \"%s\"}", CLIENT_NAME));
        event.setPathParameters(Map.of("clientId", CLIENT_ID));
        APIGatewayProxyResponseEvent result = makeHandlerRequest(event);

        assertThat(result, hasStatus(400));
        assertThat(result, hasBody(INVALID_SCOPE.toJSONObject().toJSONString()));

        verify(auditService).submitAuditEvent(UPDATE_CLIENT_REQUEST_ERROR, CLIENT_ID, USER);
    }

    private ClientRegistry createClientRegistry() {
        return new ClientRegistry()
                .withClientName(CLIENT_NAME)
                .withClientID(CLIENT_ID)
                .withPublicKey("public-key")
                .withScopes(SCOPES)
                .withSubjectType("Public")
                .withRedirectUrls(singletonList("http://localhost/redirect"))
                .withContacts(singletonList("contant-name"))
                .withPostLogoutRedirectUrls(singletonList("localhost/logout"))
                .withServiceType(SERVICE_TYPE)
                .withClientType(ClientType.WEB.getValue())
                .withClaims(List.of("claim"));
    }

    private APIGatewayProxyResponseEvent makeHandlerRequest(APIGatewayProxyRequestEvent event) {
        var response = handler.handleRequest(event, context);

        verify(auditService).submitAuditEvent(UPDATE_CLIENT_REQUEST_RECEIVED, "", USER);

        return response;
    }
}
