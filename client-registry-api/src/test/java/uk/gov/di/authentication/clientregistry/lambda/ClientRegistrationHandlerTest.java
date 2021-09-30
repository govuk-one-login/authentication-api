package uk.gov.di.authentication.clientregistry.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.id.ClientID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.clientregistry.entity.ClientRegistrationRequest;
import uk.gov.di.authentication.clientregistry.entity.ClientRegistrationResponse;
import uk.gov.di.authentication.clientregistry.services.ClientConfigValidationService;
import uk.gov.di.authentication.shared.entity.CredentialTrustLevel;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.ClientService;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.clientregistry.domain.ClientRegistryAuditableEvent.REGISTER_CLIENT_REQUEST_ERROR;
import static uk.gov.di.authentication.clientregistry.domain.ClientRegistryAuditableEvent.REGISTER_CLIENT_REQUEST_RECEIVED;
import static uk.gov.di.authentication.clientregistry.services.ClientConfigValidationService.INVALID_PUBLIC_KEY;
import static uk.gov.di.authentication.clientregistry.services.ClientConfigValidationService.INVALID_SCOPE;
import static uk.gov.di.authentication.shared.entity.ServiceType.MANDATORY;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class ClientRegistrationHandlerTest {

    private final Context context = mock(Context.class);
    private final ClientService clientService = mock(ClientService.class);
    private final ClientConfigValidationService configValidationService =
            mock(ClientConfigValidationService.class);
    private final AuditService auditService = mock(AuditService.class);
    private final ObjectMapper objectMapper = new ObjectMapper();
    private ClientRegistrationHandler handler;

    @BeforeEach
    public void setup() {
        handler =
                new ClientRegistrationHandler(clientService, configValidationService, auditService);
    }

    @AfterEach
    public void afterEach() {
        verifyNoMoreInteractions(auditService);
    }

    @Test
    public void shouldReturn200IfClientRegistrationRequestIsSuccessful()
            throws JsonProcessingException {
        String clientId = UUID.randomUUID().toString();
        String sectorIdentifierUri = "https://test.com";
        String subjectType = "public";
        String clientName = "test-client";
        List<String> redirectUris = List.of("http://localhost:8080/redirect-uri");
        List<String> contacts = List.of("joe.bloggs@test.com");
        String serviceType = String.valueOf(MANDATORY);
        String vectorsOfTrust = CredentialTrustLevel.MEDIUM_LEVEL.getValue();
        when(configValidationService.validateClientRegistrationConfig(
                        any(ClientRegistrationRequest.class)))
                .thenReturn(Optional.empty());
        when(clientService.generateClientID()).thenReturn(new ClientID(clientId));

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();

        event.setBody(
                "{ \"client_name\": \"test-client\", \"redirect_uris\": [\"http://localhost:8080/redirect-uri\"], \"contacts\": [\"joe.bloggs@test.com\"], \"scopes\": [\"openid\"],  \"public_key\": \"some-public-key\", \"post_logout_redirect_uris\": [\"http://localhost:8080/post-logout-redirect-uri\"], \"service_type\": \"MANDATORY\", \"sector_identifier_uri\": \"https://test.com\", \"subject_type\": \"public\", \"vectors_of_trust\": \"Cm\"}");
        APIGatewayProxyResponseEvent result = makeHandlerRequest(event);

        assertThat(result, hasStatus(200));
        ClientRegistrationResponse clientRegistrationResponseResult =
                objectMapper.readValue(result.getBody(), ClientRegistrationResponse.class);
        assertThat(clientRegistrationResponseResult.getClientId(), equalTo(clientId));
        assertThat(
                clientRegistrationResponseResult.getTokenAuthMethod(), equalTo("private_key_jwt"));
        assertThat(clientRegistrationResponseResult.getSubjectType(), equalTo("Public"));
        assertThat(clientRegistrationResponseResult.getScopes(), equalTo(singletonList("openid")));
        verify(clientService)
                .addClient(
                        clientId,
                        clientName,
                        redirectUris,
                        contacts,
                        singletonList("openid"),
                        "some-public-key",
                        singletonList("http://localhost:8080/post-logout-redirect-uri"),
                        serviceType,
                        sectorIdentifierUri,
                        subjectType,
                        vectorsOfTrust);
    }

    @Test
    public void shouldReturn400IfAnyRequestParametersAreMissing() {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody(
                "{\"redirect_uris\": [\"http://localhost:8080/redirect-uri\"], \"contacts\": [\"joe.bloggs@test.com\"] }");
        APIGatewayProxyResponseEvent result = makeHandlerRequest(event);

        assertThat(result, hasStatus(400));
        assertThat(result, hasBody(OAuth2Error.INVALID_REQUEST.toJSONObject().toJSONString()));

        verify(auditService).submitAuditEvent(REGISTER_CLIENT_REQUEST_ERROR);
    }

    @Test
    public void shouldReturn400ResponseIfRequestFailsValidation() {
        when(configValidationService.validateClientRegistrationConfig(
                        any(ClientRegistrationRequest.class)))
                .thenReturn(Optional.of(INVALID_PUBLIC_KEY));
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody(
                "{ \"client_name\": \"test-client\", \"redirect_uris\": [\"http://localhost:8080/redirect-uri\"], \"contacts\": [\"joe.bloggs@test.com\"], \"scopes\": [\"openid\"],  \"public_key\": \"some-public-key\", \"post_logout_redirect_uris\": [\"http://localhost:8080/post-logout-redirect-uri\"], \"service_type\": \"MANDATORY\", \"sector_identifier_uri\": \"https://test.com\", \"subject_type\": \"public\"}");
        APIGatewayProxyResponseEvent result = makeHandlerRequest(event);

        assertThat(result, hasStatus(400));
        assertThat(result, hasBody(INVALID_PUBLIC_KEY.toJSONObject().toJSONString()));

        verify(auditService).submitAuditEvent(REGISTER_CLIENT_REQUEST_ERROR);
    }

    @Test
    public void shouldReturn400ResponseIfRequestHasPrivateScope() {
        when(configValidationService.validateClientRegistrationConfig(
                        any(ClientRegistrationRequest.class)))
                .thenReturn(Optional.of(INVALID_SCOPE));
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody(
                "{ \"client_name\": \"test-client\", \"redirect_uris\": [\"http://localhost:8080/redirect-uri\"], \"contacts\": [\"joe.bloggs@test.com\"], \"scopes\": [\"openid\"],  \"public_key\": \"some-public-key\", \"post_logout_redirect_uris\": [\"http://localhost:8080/post-logout-redirect-uri\"], \"service_type\": \"MANDATORY\", \"sector_identifier_uri\": \"https://test.com\", \"subject_type\": \"public\"}");
        APIGatewayProxyResponseEvent result = makeHandlerRequest(event);

        assertThat(result, hasStatus(400));
        assertThat(result, hasBody(INVALID_SCOPE.toJSONObject().toJSONString()));

        verify(auditService).submitAuditEvent(REGISTER_CLIENT_REQUEST_ERROR);
    }

    private APIGatewayProxyResponseEvent makeHandlerRequest(APIGatewayProxyRequestEvent event) {
        var response = handler.handleRequest(event, context);

        verify(auditService).submitAuditEvent(REGISTER_CLIENT_REQUEST_RECEIVED);

        return response;
    }
}
