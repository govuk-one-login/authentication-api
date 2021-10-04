package uk.gov.di.authentication.clientregistry.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.clientregistry.entity.ClientRegistrationResponse;
import uk.gov.di.authentication.clientregistry.services.ClientConfigValidationService;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.UpdateClientConfigRequest;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.ClientService;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static java.lang.String.format;
import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
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
import static uk.gov.di.authentication.shared.entity.ServiceType.MANDATORY;
import static uk.gov.di.authentication.shared.matchers.APIGatewayProxyResponseEventMatcher.hasBody;
import static uk.gov.di.authentication.shared.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class UpdateClientConfigHandlerTest {

    private static final String CLIENT_ID = "client-id-1";
    private static final String CLIENT_NAME = "client-name-one";
    private static final List<String> SCOPES = singletonList("openid");
    private static final String SERVICE_TYPE = String.valueOf(MANDATORY);
    private final Context context = mock(Context.class);
    private final ClientService clientService = mock(ClientService.class);
    private final ClientConfigValidationService clientValidationService =
            mock(ClientConfigValidationService.class);
    private final AuditService auditService = mock(AuditService.class);
    private UpdateClientConfigHandler handler;

    @BeforeEach
    public void setUp() {
        when(context.getAwsRequestId()).thenReturn("request-id");
        handler =
                new UpdateClientConfigHandler(clientService, clientValidationService, auditService);
    }

    @AfterEach
    public void afterEach() {
        verifyNoMoreInteractions(auditService);
    }

    @Test
    public void shouldReturn200ForAValidRequest() throws JsonProcessingException {
        when(clientService.isValidClient(CLIENT_ID)).thenReturn(true);
        when(clientValidationService.validateClientUpdateConfig(
                        any(UpdateClientConfigRequest.class)))
                .thenReturn(Optional.empty());
        when(clientService.updateClient(eq(CLIENT_ID), any(UpdateClientConfigRequest.class)))
                .thenReturn(createClientRegistry());

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody(format("{\"client_name\": \"%s\"}", CLIENT_NAME));
        event.setPathParameters(Map.of("clientId", CLIENT_ID));
        APIGatewayProxyResponseEvent result = makeHandlerRequest(event);

        assertThat(result, hasStatus(200));
        ClientRegistrationResponse clientRegistrationResponse =
                new ObjectMapper().readValue(result.getBody(), ClientRegistrationResponse.class);
        assertThat(clientRegistrationResponse.getClientId(), equalTo(CLIENT_ID));
        assertThat(clientRegistrationResponse.getClientName(), equalTo(CLIENT_NAME));
        assertThat(clientRegistrationResponse.getSubjectType(), equalTo("Public"));
        assertThat(clientRegistrationResponse.getTokenAuthMethod(), equalTo("private_key_jwt"));
        assertThat(clientRegistrationResponse.getScopes(), equalTo(SCOPES));
        assertThat(clientRegistrationResponse.getServiceType(), equalTo(SERVICE_TYPE));
    }

    @Test
    public void shouldReturn400WhenRequestIsMissingClientID() {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody(format("{\"client_name\": \"%s\"}", CLIENT_NAME));
        APIGatewayProxyResponseEvent result = makeHandlerRequest(event);
        assertThat(result, hasStatus(400));
        assertThat(result, hasBody(OAuth2Error.INVALID_REQUEST.toJSONObject().toJSONString()));

        verify(auditService).submitAuditEvent(UPDATE_CLIENT_REQUEST_ERROR, "request-id", "", "");
    }

    @Test
    public void shouldReturn400WhenRequestContainsNoParameters() {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody("");
        event.setPathParameters(Map.of("clientId", CLIENT_ID));
        APIGatewayProxyResponseEvent result = makeHandlerRequest(event);
        assertThat(result, hasStatus(400));
        assertThat(result, hasBody(OAuth2Error.INVALID_REQUEST.toJSONObject().toJSONString()));

        verify(auditService).submitAuditEvent(UPDATE_CLIENT_REQUEST_ERROR, "request-id", "", "");
    }

    @Test
    public void shouldReturn401WhenClientIdIsInvalid() {
        when(clientService.isValidClient(CLIENT_ID)).thenReturn(false);

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setPathParameters(Map.of("clientId", CLIENT_ID));
        event.setBody(format("{\"client_name\": \"%s\"}", CLIENT_NAME));
        APIGatewayProxyResponseEvent result = makeHandlerRequest(event);
        assertThat(result, hasStatus(400));
        assertThat(result, hasBody(OAuth2Error.INVALID_CLIENT.toJSONObject().toJSONString()));

        verify(auditService)
                .submitAuditEvent(UPDATE_CLIENT_REQUEST_ERROR, "request-id", "", CLIENT_ID);
    }

    @Test
    public void shouldReturn400WhenRequestFailsValidation() {
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

        verify(auditService)
                .submitAuditEvent(UPDATE_CLIENT_REQUEST_ERROR, "request-id", "", CLIENT_ID);
    }

    @Test
    public void shouldReturn400WhenRequestHasInvalidScope() {
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

        verify(auditService)
                .submitAuditEvent(UPDATE_CLIENT_REQUEST_ERROR, "request-id", "", CLIENT_ID);
    }

    private ClientRegistry createClientRegistry() {
        ClientRegistry clientRegistry = new ClientRegistry();
        clientRegistry.setClientName(CLIENT_NAME);
        clientRegistry.setClientID(CLIENT_ID);
        clientRegistry.setPublicKey("public-key");
        clientRegistry.setScopes(SCOPES);
        clientRegistry.setRedirectUrls(singletonList("http://localhost/redirect"));
        clientRegistry.setContacts(singletonList("contant-name"));
        clientRegistry.setPostLogoutRedirectUrls(singletonList("localhost/logout"));
        clientRegistry.setServiceType(SERVICE_TYPE);
        return clientRegistry;
    }

    private APIGatewayProxyResponseEvent makeHandlerRequest(APIGatewayProxyRequestEvent event) {
        var response = handler.handleRequest(event, context);

        verify(auditService).submitAuditEvent(UPDATE_CLIENT_REQUEST_RECEIVED, "request-id", "", "");

        return response;
    }
}
