package uk.gov.di.orchestration.shared.services;

import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.orchestration.shared.entity.ClientSession;
import uk.gov.di.orchestration.shared.exceptions.NoSessionException;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static java.util.Collections.emptyList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class NoSessionOrchestrationServiceTest {

    private final RedisConnectionService redisConnectionService =
            mock(RedisConnectionService.class);
    private final ClientSessionService clientSessionService = mock(ClientSessionService.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    public static final String STATE_STORAGE_PREFIX = "state:";
    private static final URI REDIRECT_URI = URI.create("test-uri");
    private static final ClientID CLIENT_ID = new ClientID();
    private static final State STATE = new State();
    private static final String CLIENT_SESSION_ID = "a-client-session-id";

    private NoSessionOrchestrationService noSessionOrchestrationService;

    @BeforeEach
    void setup() {
        noSessionOrchestrationService =
                new NoSessionOrchestrationService(
                        redisConnectionService, clientSessionService, configurationService);
    }

    @Test
    void shouldSuccessfullyReturnNoSessionOrchestrationEntity()
            throws NoSessionException, ParseException {
        when(redisConnectionService.getValue(STATE_STORAGE_PREFIX + STATE.getValue()))
                .thenReturn(CLIENT_SESSION_ID);
        when(clientSessionService.getClientSession(CLIENT_SESSION_ID))
                .thenReturn(Optional.of(generateClientSession()));

        Map<String, String> queryParams = new HashMap<>();
        queryParams.put("state", STATE.getValue());
        queryParams.put("error", OAuth2Error.ACCESS_DENIED_CODE);
        queryParams.put("error_description", OAuth2Error.ACCESS_DENIED.getDescription());
        var noSessionEntity =
                noSessionOrchestrationService.generateNoSessionOrchestrationEntity(
                        queryParams, true);

        assertThat(
                noSessionEntity.getErrorObject().getCode(),
                equalTo(OAuth2Error.ACCESS_DENIED_CODE));
        assertThat(
                noSessionEntity.getErrorObject().getDescription(),
                equalTo(
                        "Access denied for security reasons, a new authentication request may be successful"));
        assertThat(noSessionEntity.getClientSessionId(), equalTo(CLIENT_SESSION_ID));

        var authenticationRequest =
                AuthenticationRequest.parse(
                        noSessionEntity.getClientSession().getAuthRequestParams());
        assertThat(authenticationRequest.getClientID(), equalTo(CLIENT_ID));
        assertThat(authenticationRequest.getRedirectionURI(), equalTo(REDIRECT_URI));
    }

    @Test
    void shouldThrowIfNoSessionResponseIsDisabled() {
        when(redisConnectionService.getValue(STATE_STORAGE_PREFIX + STATE.getValue()))
                .thenReturn(CLIENT_SESSION_ID);
        when(clientSessionService.getClientSession(CLIENT_SESSION_ID))
                .thenReturn(Optional.of(generateClientSession()));

        Map<String, String> queryParams = new HashMap<>();
        queryParams.put("state", STATE.getValue());
        queryParams.put("error", OAuth2Error.ACCESS_DENIED_CODE);
        queryParams.put("error_description", OAuth2Error.ACCESS_DENIED.getDescription());
        var noSessionException =
                assertThrows(
                        NoSessionException.class,
                        () ->
                                noSessionOrchestrationService.generateNoSessionOrchestrationEntity(
                                        queryParams, false));

        assertThat(
                noSessionException.getMessage(),
                equalTo(
                        "Session Cookie not present and access_denied or state param missing from error response. NoSessionResponseEnabled: false"));
    }

    @Test
    void shouldThrowIfErrorIsPresentButIsNotAccessDenied() {
        when(redisConnectionService.getValue(STATE_STORAGE_PREFIX + STATE.getValue()))
                .thenReturn(CLIENT_SESSION_ID);
        when(clientSessionService.getClientSession(CLIENT_SESSION_ID))
                .thenReturn(Optional.of(generateClientSession()));

        Map<String, String> queryParams = new HashMap<>();
        queryParams.put("state", STATE.getValue());
        queryParams.put("error", OAuth2Error.INVALID_CLIENT.getCode());
        queryParams.put("error_description", OAuth2Error.INVALID_CLIENT.getDescription());
        var noSessionException =
                assertThrows(
                        NoSessionException.class,
                        () ->
                                noSessionOrchestrationService.generateNoSessionOrchestrationEntity(
                                        queryParams, true));

        assertThat(
                noSessionException.getMessage(),
                equalTo(
                        "Session Cookie not present and access_denied or state param missing from error response. NoSessionResponseEnabled: true"));
    }

    @Test
    void shouldThrowIfErrorIsNotPresent() {
        when(redisConnectionService.getValue(STATE_STORAGE_PREFIX + STATE.getValue()))
                .thenReturn(CLIENT_SESSION_ID);
        when(clientSessionService.getClientSession(CLIENT_SESSION_ID))
                .thenReturn(Optional.of(generateClientSession()));

        var queryParams = Map.of("state", STATE.getValue());
        var noSessionException =
                assertThrows(
                        NoSessionException.class,
                        () ->
                                noSessionOrchestrationService.generateNoSessionOrchestrationEntity(
                                        queryParams, true));

        assertThat(
                noSessionException.getMessage(),
                equalTo(
                        "Session Cookie not present and access_denied or state param missing from error response. NoSessionResponseEnabled: true"));
    }

    @Test
    void shouldThrowIfStateIsNotPresent() {
        Map<String, String> queryParams = new HashMap<>();
        queryParams.put("error", OAuth2Error.ACCESS_DENIED_CODE);
        queryParams.put("error_description", OAuth2Error.ACCESS_DENIED.getDescription());

        var noSessionException =
                assertThrows(
                        NoSessionException.class,
                        () ->
                                noSessionOrchestrationService.generateNoSessionOrchestrationEntity(
                                        queryParams, true));

        assertThat(
                noSessionException.getMessage(),
                equalTo(
                        "Session Cookie not present and access_denied or state param missing from error response. NoSessionResponseEnabled: true"));
    }

    @Test
    void shouldThrowIfStateIsPresentButEmpty() {
        Map<String, String> queryParams = new HashMap<>();
        queryParams.put("error", OAuth2Error.ACCESS_DENIED_CODE);
        queryParams.put("error_description", OAuth2Error.ACCESS_DENIED.getDescription());
        queryParams.put("state", "");

        var noSessionException =
                assertThrows(
                        NoSessionException.class,
                        () ->
                                noSessionOrchestrationService.generateNoSessionOrchestrationEntity(
                                        queryParams, true));

        assertThat(
                noSessionException.getMessage(),
                equalTo(
                        "Session Cookie not present and access_denied or state param missing from error response. NoSessionResponseEnabled: true"));
    }

    @Test
    void shouldThrowIfNoClientSessionIdIsFoundWithState() {
        when(redisConnectionService.getValue(STATE_STORAGE_PREFIX + STATE.getValue()))
                .thenReturn(null);

        Map<String, String> queryParams = new HashMap<>();
        queryParams.put("state", STATE.getValue());
        queryParams.put("error", OAuth2Error.ACCESS_DENIED_CODE);
        queryParams.put("error_description", OAuth2Error.ACCESS_DENIED.getDescription());

        var noSessionException =
                assertThrows(
                        NoSessionException.class,
                        () ->
                                noSessionOrchestrationService.generateNoSessionOrchestrationEntity(
                                        queryParams, true));

        assertThat(
                noSessionException.getMessage(),
                equalTo("ClientSessionId could not be found using state param"));
    }

    @Test
    void shouldThrowIfNoClientSessionIsFoundWithClientSessionId() {
        when(redisConnectionService.getValue(STATE_STORAGE_PREFIX + STATE.getValue()))
                .thenReturn(CLIENT_SESSION_ID);
        when(clientSessionService.getClientSession(CLIENT_SESSION_ID)).thenReturn(Optional.empty());

        Map<String, String> queryParams = new HashMap<>();
        queryParams.put("state", STATE.getValue());
        queryParams.put("error", OAuth2Error.ACCESS_DENIED_CODE);
        queryParams.put("error_description", OAuth2Error.ACCESS_DENIED.getDescription());

        var noSessionException =
                assertThrows(
                        NoSessionException.class,
                        () ->
                                noSessionOrchestrationService.generateNoSessionOrchestrationEntity(
                                        queryParams, true));

        assertThat(
                noSessionException.getMessage(),
                equalTo("No client session found with given client sessionId"));
    }

    @Test
    void shouldCallRedisAndSaveClientSessionIdAgainstState() {
        when(configurationService.getSessionExpiry()).thenReturn(7200L);
        noSessionOrchestrationService.storeClientSessionIdAgainstState(CLIENT_SESSION_ID, STATE);

        verify(redisConnectionService)
                .saveWithExpiry("state:" + STATE.getValue(), CLIENT_SESSION_ID, 7200);
    }

    private static ClientSession generateClientSession() {
        var responseType = new ResponseType(ResponseType.Value.CODE);
        var scope = new Scope();
        scope.add(OIDCScopeValue.OPENID);
        scope.add("phone");
        scope.add("email");
        var authRequest =
                new AuthenticationRequest.Builder(responseType, scope, CLIENT_ID, REDIRECT_URI)
                        .state(new State())
                        .nonce(new Nonce())
                        .build();
        return new ClientSession(authRequest.toParameters(), null, emptyList(), null);
    }
}
