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
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.authentication.clientregistry.entity.ClientRegistrationRequest;
import uk.gov.di.authentication.clientregistry.entity.ClientRegistrationResponse;
import uk.gov.di.authentication.clientregistry.services.ClientConfigValidationService;
import uk.gov.di.authentication.shared.entity.ClientType;
import uk.gov.di.authentication.shared.helpers.IdGenerator;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.sharedtest.logging.CaptureLoggingExtension;

import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

import static java.lang.String.format;
import static java.util.Collections.emptyList;
import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.not;
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
import static uk.gov.di.authentication.sharedtest.logging.LogEventMatcher.withMessageContaining;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class ClientRegistrationHandlerTest {

    public static final String CLIENT_NAME = "test-client";
    private static final String SECTOR_IDENTIFIER = "https://test.com";
    private static final String SUBJECT_TYPE = "pairwise";
    private static final List<String> REDIRECT_URIS = List.of("http://localhost:8080/redirect-uri");
    private static final List<String> CONTACTS = List.of("joe.bloggs@test.com");
    private static final String SERVICE_TYPE = String.valueOf(MANDATORY);
    private final String clientId = IdGenerator.generate();
    private final Context context = mock(Context.class);
    private final ClientService clientService = mock(ClientService.class);
    private final ClientConfigValidationService configValidationService =
            mock(ClientConfigValidationService.class);
    private final AuditService auditService = mock(AuditService.class);
    private final ObjectMapper objectMapper = new ObjectMapper();
    private ClientRegistrationHandler handler;

    @BeforeEach
    public void setup() {
        when(context.getAwsRequestId()).thenReturn("request-id");
        handler =
                new ClientRegistrationHandler(clientService, configValidationService, auditService);
    }

    @RegisterExtension
    public final CaptureLoggingExtension logging =
            new CaptureLoggingExtension(UpdateClientConfigHandler.class);

    @AfterEach
    public void afterEach() {
        assertThat(logging.events(), not(hasItem(withMessageContaining(clientId))));
        verifyNoMoreInteractions(auditService);
    }

    @Test
    void shouldReturn200IfClientRegistrationRequestIsSuccessful() throws JsonProcessingException {
        when(configValidationService.validateClientRegistrationConfig(
                        any(ClientRegistrationRequest.class)))
                .thenReturn(Optional.empty());
        when(clientService.generateClientID()).thenReturn(new ClientID(clientId));

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();

        event.setBody(
                "{ \"client_name\": \"test-client\", \"redirect_uris\": [\"http://localhost:8080/redirect-uri\"], \"contacts\": [\"joe.bloggs@test.com\"], \"scopes\": [\"openid\"],  \"public_key\": \"some-public-key\", \"post_logout_redirect_uris\": [\"http://localhost:8080/post-logout-redirect-uri\"], \"back_channel_logout_uri\": \"http://localhost:8080/back-channel-logout-uri\", \"service_type\": \"MANDATORY\", \"sector_identifier_uri\": \"https://test.com\", \"subject_type\": \"pairwise\"}");
        APIGatewayProxyResponseEvent result = makeHandlerRequest(event);

        assertThat(result, hasStatus(200));
        ClientRegistrationResponse clientRegistrationResponseResult =
                objectMapper.readValue(result.getBody(), ClientRegistrationResponse.class);
        assertThat(clientRegistrationResponseResult.getClientId(), equalTo(clientId));
        assertThat(
                clientRegistrationResponseResult.getTokenAuthMethod(), equalTo("private_key_jwt"));
        assertThat(clientRegistrationResponseResult.getSubjectType(), equalTo(SUBJECT_TYPE));
        assertThat(clientRegistrationResponseResult.getScopes(), equalTo(singletonList("openid")));
        verify(clientService)
                .addClient(
                        clientId,
                        CLIENT_NAME,
                        REDIRECT_URIS,
                        CONTACTS,
                        singletonList("openid"),
                        "some-public-key",
                        singletonList("http://localhost:8080/post-logout-redirect-uri"),
                        "http://localhost:8080/back-channel-logout-uri",
                        SERVICE_TYPE,
                        SECTOR_IDENTIFIER,
                        SUBJECT_TYPE,
                        true,
                        emptyList(),
                        ClientType.WEB.getValue());
    }

    @Test
    void shouldSetConsentRequiredToFalseWhenIdentityVerificationIsRequired()
            throws JsonProcessingException {
        when(configValidationService.validateClientRegistrationConfig(
                        any(ClientRegistrationRequest.class)))
                .thenReturn(Optional.empty());
        when(clientService.generateClientID()).thenReturn(new ClientID(clientId));

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();

        event.setBody(
                "{ \"client_name\": \"test-client\", \"redirect_uris\": [\"http://localhost:8080/redirect-uri\"], \"contacts\": [\"joe.bloggs@test.com\"], \"scopes\": [\"openid\"],  \"public_key\": \"some-public-key\", \"post_logout_redirect_uris\": [\"http://localhost:8080/post-logout-redirect-uri\"], \"back_channel_logout_uri\": \"http://localhost:8080/back-channel-logout-uri\", \"sector_identifier_uri\": \"https://test.com\", \"subject_type\": \"pairwise\",  \"identity_verification_required\": \"true\"}");
        APIGatewayProxyResponseEvent result = makeHandlerRequest(event);

        assertThat(result, hasStatus(200));
        ClientRegistrationResponse clientRegistrationResponseResult =
                objectMapper.readValue(result.getBody(), ClientRegistrationResponse.class);
        assertThat(clientRegistrationResponseResult.getClientId(), equalTo(clientId));
        assertThat(
                clientRegistrationResponseResult.getTokenAuthMethod(), equalTo("private_key_jwt"));
        assertThat(clientRegistrationResponseResult.getSubjectType(), equalTo(SUBJECT_TYPE));
        assertThat(clientRegistrationResponseResult.getScopes(), equalTo(singletonList("openid")));
        verify(clientService)
                .addClient(
                        clientId,
                        CLIENT_NAME,
                        REDIRECT_URIS,
                        CONTACTS,
                        singletonList("openid"),
                        "some-public-key",
                        singletonList("http://localhost:8080/post-logout-redirect-uri"),
                        "http://localhost:8080/back-channel-logout-uri",
                        SERVICE_TYPE,
                        SECTOR_IDENTIFIER,
                        SUBJECT_TYPE,
                        false,
                        emptyList(),
                        ClientType.WEB.getValue());
    }

    @Test
    void shouldAllowBackChannelLogoutUriToBeAbsent() {
        when(configValidationService.validateClientRegistrationConfig(
                        any(ClientRegistrationRequest.class)))
                .thenReturn(Optional.empty());
        when(clientService.generateClientID()).thenReturn(new ClientID(clientId));

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();

        event.setBody(
                "{ \"client_name\": \"test-client\", \"redirect_uris\": [\"http://localhost:8080/redirect-uri\"], \"contacts\": [\"joe.bloggs@test.com\"], \"scopes\": [\"openid\"],  \"public_key\": \"some-public-key\", \"post_logout_redirect_uris\": [\"http://localhost:8080/post-logout-redirect-uri\"], \"service_type\": \"MANDATORY\", \"sector_identifier_uri\": \"https://test.com\", \"subject_type\": \"pairwise\"}");
        APIGatewayProxyResponseEvent result = makeHandlerRequest(event);

        assertThat(result, hasStatus(200));
        verify(clientService)
                .addClient(
                        clientId,
                        CLIENT_NAME,
                        REDIRECT_URIS,
                        CONTACTS,
                        singletonList("openid"),
                        "some-public-key",
                        singletonList("http://localhost:8080/post-logout-redirect-uri"),
                        null,
                        SERVICE_TYPE,
                        SECTOR_IDENTIFIER,
                        SUBJECT_TYPE,
                        true,
                        emptyList(),
                        ClientType.WEB.getValue());
    }

    @Test
    void shouldReturn400IfAnyRequestParametersAreMissing() {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody(
                "{\"redirect_uris\": [\"http://localhost:8080/redirect-uri\"], \"contacts\": [\"joe.bloggs@test.com\"] }");
        APIGatewayProxyResponseEvent result = makeHandlerRequest(event);

        assertThat(result, hasStatus(400));
        assertThat(result, hasBody(OAuth2Error.INVALID_REQUEST.toJSONObject().toJSONString()));

        verify(auditService)
                .submitAuditEvent(
                        REGISTER_CLIENT_REQUEST_ERROR, "request-id", "", "", "", "", "", "", "");
    }

    @Test
    void shouldReturn400ResponseIfRequestFailsValidation() {
        when(configValidationService.validateClientRegistrationConfig(
                        any(ClientRegistrationRequest.class)))
                .thenReturn(Optional.of(INVALID_PUBLIC_KEY));
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody(
                "{ \"client_name\": \"test-client\", \"redirect_uris\": [\"http://localhost:8080/redirect-uri\"], \"contacts\": [\"joe.bloggs@test.com\"], \"scopes\": [\"openid\"],  \"public_key\": \"some-public-key\", \"post_logout_redirect_uris\": [\"http://localhost:8080/post-logout-redirect-uri\"], \"back_channel_logout_uri\": \"http://localhost:8080/back-channel-logout-uri\", \"service_type\": \"MANDATORY\", \"sector_identifier_uri\": \"https://test.com\", \"subject_type\": \"public\", \"identity_verification_required\": \"false\"}");
        APIGatewayProxyResponseEvent result = makeHandlerRequest(event);

        assertThat(result, hasStatus(400));
        assertThat(result, hasBody(INVALID_PUBLIC_KEY.toJSONObject().toJSONString()));

        verify(auditService)
                .submitAuditEvent(
                        REGISTER_CLIENT_REQUEST_ERROR, "request-id", "", "", "", "", "", "", "");
    }

    @Test
    void shouldReturn400ResponseIfRequestHasPrivateScope() {
        when(configValidationService.validateClientRegistrationConfig(
                        any(ClientRegistrationRequest.class)))
                .thenReturn(Optional.of(INVALID_SCOPE));
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody(
                "{ \"client_name\": \"test-client\", \"redirect_uris\": [\"http://localhost:8080/redirect-uri\"], \"contacts\": [\"joe.bloggs@test.com\"], \"scopes\": [\"openid\"],  \"public_key\": \"some-public-key\", \"post_logout_redirect_uris\": [\"http://localhost:8080/post-logout-redirect-uri\"], \"back_channel_logout_uri\": \"http://localhost:8080/back-channel-logout-uri\", \"service_type\": \"MANDATORY\", \"sector_identifier_uri\": \"https://test.com\", \"subject_type\": \"public\", \"identity_verification_required\": \"false\"}");
        APIGatewayProxyResponseEvent result = makeHandlerRequest(event);

        assertThat(result, hasStatus(400));
        assertThat(result, hasBody(INVALID_SCOPE.toJSONObject().toJSONString()));

        verify(auditService)
                .submitAuditEvent(
                        REGISTER_CLIENT_REQUEST_ERROR, "request-id", "", "", "", "", "", "", "");
    }

    private static Stream<String> clientTypes() {
        return Stream.of(ClientType.WEB.getValue(), ClientType.APP.getValue());
    }

    @ParameterizedTest
    @MethodSource("clientTypes")
    void shouldReturnExpectedClientTypeInResponse(String clientType)
            throws JsonProcessingException {
        when(configValidationService.validateClientRegistrationConfig(
                        any(ClientRegistrationRequest.class)))
                .thenReturn(Optional.empty());
        when(clientService.generateClientID()).thenReturn(new ClientID(clientId));

        var event = new APIGatewayProxyRequestEvent();
        event.setBody(
                format(
                        "{ \"client_name\": \"%s\", "
                                + "\"redirect_uris\": [\"http://localhost:8080/redirect-uri\"], "
                                + "\"contacts\": [\"joe.bloggs@test.com\"], "
                                + "\"scopes\": [\"openid\"],  "
                                + "\"public_key\": \"some-public-key\", "
                                + "\"post_logout_redirect_uris\": [\"http://localhost:8080/post-logout-redirect-uri\"], "
                                + "\"back_channel_logout_uri\": \"http://localhost:8080/back-channel-logout\", "
                                + "\"service_type\": \"%s\", "
                                + "\"sector_identifier_uri\": \"%s\", "
                                + "\"subject_type\": \"%s\", "
                                + "\"client_type\": \"%s\" }",
                        CLIENT_NAME, MANDATORY, SECTOR_IDENTIFIER, SUBJECT_TYPE, clientType));
        var result = makeHandlerRequest(event);

        assertThat(result, hasStatus(200));
        var clientRegistrationResponseResult =
                objectMapper.readValue(result.getBody(), ClientRegistrationResponse.class);

        assertThat(clientRegistrationResponseResult.getClientType(), equalTo(clientType));
    }

    private APIGatewayProxyResponseEvent makeHandlerRequest(APIGatewayProxyRequestEvent event) {
        var response = handler.handleRequest(event, context);

        verify(auditService)
                .submitAuditEvent(
                        REGISTER_CLIENT_REQUEST_RECEIVED, "request-id", "", "", "", "", "", "", "");

        return response;
    }
}
