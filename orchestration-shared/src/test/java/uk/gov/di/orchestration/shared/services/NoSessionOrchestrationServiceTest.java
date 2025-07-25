package uk.gov.di.orchestration.shared.services;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
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
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import uk.gov.di.orchestration.shared.entity.OrchClientSessionItem;
import uk.gov.di.orchestration.shared.exceptions.NoSessionException;
import uk.gov.di.orchestration.shared.helpers.IdGenerator;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static java.util.Collections.emptyList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class NoSessionOrchestrationServiceTest {

    private final RedisConnectionService redisConnectionService =
            mock(RedisConnectionService.class);
    private final OrchClientSessionService orchClientSessionService =
            mock(OrchClientSessionService.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    public static final String STATE_STORAGE_PREFIX = "state:";
    private static final URI REDIRECT_URI = URI.create("test-uri");
    private static final ClientID CLIENT_ID = new ClientID();
    private static final State STATE = new State();
    private static final Nonce NONCE = new Nonce();
    private static final String CLIENT_SESSION_ID = "a-client-session-id";
    private NoSessionOrchestrationService noSessionOrchestrationService;

    @BeforeEach
    void setup() {
        noSessionOrchestrationService =
                new NoSessionOrchestrationService(
                        redisConnectionService, orchClientSessionService, configurationService);
    }

    @Test
    void shouldSuccessfullyReturnNoSessionOrchestrationEntity()
            throws NoSessionException, ParseException {
        when(redisConnectionService.getValue(STATE_STORAGE_PREFIX + STATE.getValue()))
                .thenReturn(CLIENT_SESSION_ID);
        when(orchClientSessionService.getClientSession(CLIENT_SESSION_ID))
                .thenReturn(Optional.of(generateOrchClientSession()));

        Map<String, String> queryParams = new HashMap<>();
        queryParams.put("state", STATE.getValue());
        queryParams.put("error", OAuth2Error.ACCESS_DENIED_CODE);
        queryParams.put("error_description", OAuth2Error.ACCESS_DENIED.getDescription());
        var noSessionEntity =
                noSessionOrchestrationService.generateNoSessionOrchestrationEntity(queryParams);

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
    void shouldThrowIfErrorIsPresentButIsNotAccessDenied() {
        when(redisConnectionService.getValue(STATE_STORAGE_PREFIX + STATE.getValue()))
                .thenReturn(CLIENT_SESSION_ID);
        when(orchClientSessionService.getClientSession(CLIENT_SESSION_ID))
                .thenReturn(Optional.of(generateOrchClientSession()));

        Map<String, String> queryParams = new HashMap<>();
        queryParams.put("state", STATE.getValue());
        queryParams.put("error", OAuth2Error.INVALID_CLIENT.getCode());
        queryParams.put("error_description", OAuth2Error.INVALID_CLIENT.getDescription());
        var noSessionException =
                assertThrows(
                        NoSessionException.class,
                        () ->
                                noSessionOrchestrationService.generateNoSessionOrchestrationEntity(
                                        queryParams));

        assertThat(
                noSessionException.getMessage(),
                equalTo(
                        "Session Cookie not present and access_denied or state param missing from error response"));
    }

    @Test
    void shouldThrowIfErrorIsNotPresent() {
        when(redisConnectionService.getValue(STATE_STORAGE_PREFIX + STATE.getValue()))
                .thenReturn(CLIENT_SESSION_ID);
        when(orchClientSessionService.getClientSession(CLIENT_SESSION_ID))
                .thenReturn(Optional.of(generateOrchClientSession()));

        var queryParams = Map.of("state", STATE.getValue());
        var noSessionException =
                assertThrows(
                        NoSessionException.class,
                        () ->
                                noSessionOrchestrationService.generateNoSessionOrchestrationEntity(
                                        queryParams));

        assertThat(
                noSessionException.getMessage(),
                equalTo(
                        "Session Cookie not present and access_denied or state param missing from error response"));
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
                                        queryParams));

        assertThat(
                noSessionException.getMessage(),
                equalTo(
                        "Session Cookie not present and access_denied or state param missing from error response"));
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
                                        queryParams));

        assertThat(
                noSessionException.getMessage(),
                equalTo(
                        "Session Cookie not present and access_denied or state param missing from error response"));
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
                                        queryParams));

        assertThat(
                noSessionException.getMessage(),
                equalTo("ClientSessionId could not be found using state param"));
    }

    @Test
    void shouldThrowIfNoClientSessionIsFoundWithClientSessionId() {
        when(redisConnectionService.getValue(STATE_STORAGE_PREFIX + STATE.getValue()))
                .thenReturn(CLIENT_SESSION_ID);
        when(orchClientSessionService.getClientSession(CLIENT_SESSION_ID))
                .thenReturn(Optional.empty());

        Map<String, String> queryParams = new HashMap<>();
        queryParams.put("state", STATE.getValue());
        queryParams.put("error", OAuth2Error.ACCESS_DENIED_CODE);
        queryParams.put("error_description", OAuth2Error.ACCESS_DENIED.getDescription());

        var noSessionException =
                assertThrows(
                        NoSessionException.class,
                        () ->
                                noSessionOrchestrationService.generateNoSessionOrchestrationEntity(
                                        queryParams));

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

    @Nested
    class MismatchInClientSessionIdHandling {

        @Test
        void itShouldThrowNoSessionExceptionIfAccessDeniedErrorWithNoState() {
            when(redisConnectionService.getValue(STATE_STORAGE_PREFIX + STATE.getValue()))
                    .thenReturn(CLIENT_SESSION_ID);
            when(orchClientSessionService.getClientSession(CLIENT_SESSION_ID))
                    .thenReturn(Optional.of(generateOrchClientSession()));

            Map<String, String> queryParams = new HashMap<>();
            queryParams.put("error", OAuth2Error.ACCESS_DENIED_CODE);
            queryParams.put("error_description", OAuth2Error.ACCESS_DENIED.getDescription());

            assertThrows(
                    NoSessionException.class,
                    () ->
                            noSessionOrchestrationService
                                    .generateEntityForMismatchInClientSessionId(
                                            queryParams, CLIENT_SESSION_ID));
        }

        @Test
        void itShouldReturnANoSessionEntityIfThereIsMismatchInCSIDFromSuccessfulIPVCallback()
                throws NoSessionException, ParseException {
            when(redisConnectionService.getValue(STATE_STORAGE_PREFIX + STATE.getValue()))
                    .thenReturn(CLIENT_SESSION_ID);
            when(orchClientSessionService.getClientSession(CLIENT_SESSION_ID))
                    .thenReturn(Optional.of(generateOrchClientSession()));

            Map<String, String> queryParams = new HashMap<>();
            queryParams.put("state", STATE.getValue());
            queryParams.put("code", new AuthorizationCode().getValue());

            var noSessionEntity =
                    noSessionOrchestrationService.generateEntityForMismatchInClientSessionId(
                            queryParams, IdGenerator.generate());

            assertTrue(noSessionEntity.isPresent());
            assertThat(
                    noSessionEntity.get().getErrorObject().getCode(),
                    equalTo(OAuth2Error.ACCESS_DENIED_CODE));
            assertThat(
                    noSessionEntity.get().getErrorObject().getDescription(),
                    equalTo(
                            "Access denied for security reasons, a new authentication request may be successful"));
            assertThat(noSessionEntity.get().getClientSessionId(), equalTo(CLIENT_SESSION_ID));

            var authenticationRequest =
                    AuthenticationRequest.parse(
                            noSessionEntity.get().getClientSession().getAuthRequestParams());
            assertThat(authenticationRequest.getClientID(), equalTo(CLIENT_ID));
            assertThat(authenticationRequest.getRedirectionURI(), equalTo(REDIRECT_URI));
        }

        @Test
        void itShouldGenerateANoSessionEntityWhenCSIDCookieDoesNotMatchStateValue()
                throws NoSessionException, ParseException {
            when(redisConnectionService.getValue(STATE_STORAGE_PREFIX + STATE.getValue()))
                    .thenReturn(CLIENT_SESSION_ID);
            when(orchClientSessionService.getClientSession(CLIENT_SESSION_ID))
                    .thenReturn(Optional.of(generateOrchClientSession()));

            var cookieClientSessionID = IdGenerator.generate();
            Map<String, String> queryParams = new HashMap<>();
            queryParams.put("state", STATE.getValue());
            queryParams.put("error", OAuth2Error.ACCESS_DENIED_CODE);
            queryParams.put("error_description", OAuth2Error.ACCESS_DENIED.getDescription());
            var noSessionEntity =
                    noSessionOrchestrationService.generateEntityForMismatchInClientSessionId(
                            queryParams, cookieClientSessionID);

            assertTrue(noSessionEntity.isPresent());
            assertThat(
                    noSessionEntity.get().getErrorObject().getCode(),
                    equalTo(OAuth2Error.ACCESS_DENIED_CODE));
            assertThat(
                    noSessionEntity.get().getErrorObject().getDescription(),
                    equalTo(
                            "Access denied for security reasons, a new authentication request may be successful"));
            assertThat(noSessionEntity.get().getClientSessionId(), equalTo(CLIENT_SESSION_ID));

            var authenticationRequest =
                    AuthenticationRequest.parse(
                            noSessionEntity.get().getClientSession().getAuthRequestParams());
            assertThat(authenticationRequest.getClientID(), equalTo(CLIENT_ID));
            assertThat(authenticationRequest.getRedirectionURI(), equalTo(REDIRECT_URI));
        }

        @Test
        void itShouldReturnEmptyIfClientSessionIdInCookieMatchesStateValue()
                throws NoSessionException {
            when(redisConnectionService.getValue(STATE_STORAGE_PREFIX + STATE.getValue()))
                    .thenReturn(CLIENT_SESSION_ID);
            when(orchClientSessionService.getClientSession(CLIENT_SESSION_ID))
                    .thenReturn(Optional.of(generateOrchClientSession()));

            Map<String, String> queryParams = new HashMap<>();
            queryParams.put("state", STATE.getValue());
            queryParams.put("error", OAuth2Error.ACCESS_DENIED_CODE);
            queryParams.put("error_description", OAuth2Error.ACCESS_DENIED.getDescription());
            var noSessionEntity =
                    noSessionOrchestrationService.generateEntityForMismatchInClientSessionId(
                            queryParams, CLIENT_SESSION_ID);

            assertTrue(noSessionEntity.isEmpty());
        }

        @Test
        void itShouldThrowIfThereIsNoClientSessionIdAssociatedWithStateValue() {
            when(redisConnectionService.getValue(STATE_STORAGE_PREFIX + STATE.getValue()))
                    .thenReturn(null);
            when(orchClientSessionService.getClientSession(CLIENT_SESSION_ID))
                    .thenReturn(Optional.of(generateOrchClientSession()));

            Map<String, String> queryParams = new HashMap<>();
            queryParams.put("error", OAuth2Error.ACCESS_DENIED_CODE);
            queryParams.put("error_description", OAuth2Error.ACCESS_DENIED.getDescription());
            queryParams.put("state", STATE.getValue());

            assertThrows(
                    NoSessionException.class,
                    () ->
                            noSessionOrchestrationService
                                    .generateEntityForMismatchInClientSessionId(
                                            queryParams, CLIENT_SESSION_ID));
        }

        @Test
        void
                itShouldThrowIfThereIsAMismatchBetweenCookieAndStateAndClientSessionCannotBeRetrievedFromStateValue() {
            var clientSessionIdFromState = IdGenerator.generate();

            when(redisConnectionService.getValue(STATE_STORAGE_PREFIX + STATE.getValue()))
                    .thenReturn(clientSessionIdFromState);
            when(orchClientSessionService.getClientSession(clientSessionIdFromState))
                    .thenReturn(Optional.empty());

            Map<String, String> queryParams = new HashMap<>();
            queryParams.put("error", OAuth2Error.ACCESS_DENIED_CODE);
            queryParams.put("error_description", OAuth2Error.ACCESS_DENIED.getDescription());
            queryParams.put("state", STATE.getValue());

            assertThrows(
                    NoSessionException.class,
                    () ->
                            noSessionOrchestrationService
                                    .generateEntityForMismatchInClientSessionId(
                                            queryParams, CLIENT_SESSION_ID));
        }
    }

    private static OrchClientSessionItem generateOrchClientSession() {
        var responseType = new ResponseType(ResponseType.Value.CODE);
        var scope = new Scope();
        scope.add(OIDCScopeValue.OPENID);
        scope.add("phone");
        scope.add("email");
        var authRequest =
                new AuthenticationRequest.Builder(responseType, scope, CLIENT_ID, REDIRECT_URI)
                        .state(STATE)
                        .nonce(NONCE)
                        .build();
        return new OrchClientSessionItem(
                CLIENT_SESSION_ID, authRequest.toParameters(), null, emptyList(), null);
    }
}
