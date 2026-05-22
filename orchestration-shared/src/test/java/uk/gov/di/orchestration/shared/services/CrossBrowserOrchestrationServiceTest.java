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
import uk.gov.di.orchestration.shared.entity.CrossBrowserItem;
import uk.gov.di.orchestration.shared.entity.OrchClientSessionItem;
import uk.gov.di.orchestration.shared.entity.OrchSessionItem;
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

// QualityGateUnitTest
class CrossBrowserOrchestrationServiceTest {

    private final OrchClientSessionService orchClientSessionService =
            mock(OrchClientSessionService.class);
    private final CrossBrowserStorageService crossBrowserStorageService =
            mock(CrossBrowserStorageService.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);

    private static final URI REDIRECT_URI = URI.create("test-uri");
    private static final ClientID CLIENT_ID = new ClientID();
    private static final State STATE = new State();
    private static final Nonce NONCE = new Nonce();
    private static final String CLIENT_SESSION_ID = "a-client-session-id";
    private static final OrchSessionItem ORCH_SESSION_ITEM =
            new OrchSessionItem("a-session-id").addClientSession(CLIENT_SESSION_ID);

    private CrossBrowserOrchestrationService crossBrowserOrchestrationService;

    @BeforeEach
    void setup() {
        crossBrowserOrchestrationService =
                new CrossBrowserOrchestrationService(
                        orchClientSessionService, crossBrowserStorageService);
    }

    // QualityGateRegressionTest
    @Test
    void shouldSuccessfullyReturnNoSessionOrchestrationEntity()
            throws NoSessionException, ParseException {
        when(crossBrowserStorageService.getClientSessionId(STATE))
                .thenReturn(Optional.of(CLIENT_SESSION_ID));
        when(orchClientSessionService.getClientSession(CLIENT_SESSION_ID))
                .thenReturn(Optional.of(generateOrchClientSession()));

        Map<String, String> queryParams = new HashMap<>();
        queryParams.put("state", STATE.getValue());
        queryParams.put("error", OAuth2Error.ACCESS_DENIED_CODE);
        queryParams.put("error_description", OAuth2Error.ACCESS_DENIED.getDescription());
        var noSessionEntity =
                crossBrowserOrchestrationService.generateNoSessionOrchestrationEntity(queryParams);

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

    // QualityGateRegressionTest
    @Test
    void shouldThrowIfErrorIsPresentButIsNotAccessDenied() {
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
                                crossBrowserOrchestrationService
                                        .generateNoSessionOrchestrationEntity(queryParams));

        assertThat(
                noSessionException.getMessage(),
                equalTo(
                        "Session Cookie not present and access_denied or state param missing from error response"));
    }

    // QualityGateRegressionTest
    @Test
    void shouldThrowIfErrorIsNotPresent() {
        when(orchClientSessionService.getClientSession(CLIENT_SESSION_ID))
                .thenReturn(Optional.of(generateOrchClientSession()));

        var queryParams = Map.of("state", STATE.getValue());
        var noSessionException =
                assertThrows(
                        NoSessionException.class,
                        () ->
                                crossBrowserOrchestrationService
                                        .generateNoSessionOrchestrationEntity(queryParams));

        assertThat(
                noSessionException.getMessage(),
                equalTo(
                        "Session Cookie not present and access_denied or state param missing from error response"));
    }

    // QualityGateRegressionTest
    @Test
    void shouldThrowIfStateIsNotPresent() {
        Map<String, String> queryParams = new HashMap<>();
        queryParams.put("error", OAuth2Error.ACCESS_DENIED_CODE);
        queryParams.put("error_description", OAuth2Error.ACCESS_DENIED.getDescription());

        var noSessionException =
                assertThrows(
                        NoSessionException.class,
                        () ->
                                crossBrowserOrchestrationService
                                        .generateNoSessionOrchestrationEntity(queryParams));

        assertThat(
                noSessionException.getMessage(),
                equalTo(
                        "Session Cookie not present and access_denied or state param missing from error response"));
    }

    // QualityGateRegressionTest
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
                                crossBrowserOrchestrationService
                                        .generateNoSessionOrchestrationEntity(queryParams));

        assertThat(
                noSessionException.getMessage(),
                equalTo(
                        "Session Cookie not present and access_denied or state param missing from error response"));
    }

    // QualityGateRegressionTest
    @Test
    void shouldThrowIfNoClientSessionIdIsFoundWithState() {
        Map<String, String> queryParams = new HashMap<>();
        queryParams.put("state", STATE.getValue());
        queryParams.put("error", OAuth2Error.ACCESS_DENIED_CODE);
        queryParams.put("error_description", OAuth2Error.ACCESS_DENIED.getDescription());

        var noSessionException =
                assertThrows(
                        NoSessionException.class,
                        () ->
                                crossBrowserOrchestrationService
                                        .generateNoSessionOrchestrationEntity(queryParams));

        assertThat(
                noSessionException.getMessage(),
                equalTo("ClientSessionId could not be found using state param"));
    }

    // QualityGateRegressionTest
    @Test
    void shouldThrowIfNoClientSessionIsFoundWithClientSessionId() {
        when(crossBrowserStorageService.getClientSessionId(STATE))
                .thenReturn(Optional.of(CLIENT_SESSION_ID));
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
                                crossBrowserOrchestrationService
                                        .generateNoSessionOrchestrationEntity(queryParams));

        assertThat(
                noSessionException.getMessage(),
                equalTo("No client session found with given client sessionId"));
    }

    // QualityGateRegressionTest
    @Test
    void shouldSaveClientSessionIdAgainstState() {
        when(configurationService.getSessionExpiry()).thenReturn(7200L);

        crossBrowserOrchestrationService.storeClientSessionIdAgainstState(CLIENT_SESSION_ID, STATE);

        verify(crossBrowserStorageService)
                .storeItem(new CrossBrowserItem(STATE, CLIENT_SESSION_ID));
    }

    @Nested
    class MismatchInClientSessionIdHandling {

        // QualityGateRegressionTest
        @Test
        void itShouldThrowNoSessionExceptionIfAccessDeniedErrorWithNoState() {
            when(crossBrowserStorageService.getClientSessionId(STATE))
                    .thenReturn(Optional.of(CLIENT_SESSION_ID));
            when(orchClientSessionService.getClientSession(CLIENT_SESSION_ID))
                    .thenReturn(Optional.of(generateOrchClientSession()));

            Map<String, String> queryParams = new HashMap<>();
            queryParams.put("error", OAuth2Error.ACCESS_DENIED_CODE);
            queryParams.put("error_description", OAuth2Error.ACCESS_DENIED.getDescription());

            assertThrows(
                    NoSessionException.class,
                    () ->
                            crossBrowserOrchestrationService
                                    .generateEntityForMismatchInClientSessionId(
                                            queryParams, CLIENT_SESSION_ID, ORCH_SESSION_ITEM));
        }

        // QualityGateRegressionTest
        @Test
        void itShouldReturnANoSessionEntityIfThereIsMismatchInCSIDFromSuccessfulIPVCallback()
                throws NoSessionException, ParseException {
            when(crossBrowserStorageService.getClientSessionId(STATE))
                    .thenReturn(Optional.of(CLIENT_SESSION_ID));
            when(orchClientSessionService.getClientSession(CLIENT_SESSION_ID))
                    .thenReturn(Optional.of(generateOrchClientSession()));

            Map<String, String> queryParams = new HashMap<>();
            queryParams.put("state", STATE.getValue());
            queryParams.put("code", new AuthorizationCode().getValue());

            var noSessionEntity =
                    crossBrowserOrchestrationService.generateEntityForMismatchInClientSessionId(
                            queryParams, IdGenerator.generate(), ORCH_SESSION_ITEM);

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

        // QualityGateRegressionTest
        @Test
        void itShouldGenerateANoSessionEntityWhenCSIDCookieDoesNotMatchStateValue()
                throws NoSessionException, ParseException {
            when(crossBrowserStorageService.getClientSessionId(STATE))
                    .thenReturn(Optional.of(CLIENT_SESSION_ID));
            when(orchClientSessionService.getClientSession(CLIENT_SESSION_ID))
                    .thenReturn(Optional.of(generateOrchClientSession()));

            var cookieClientSessionID = IdGenerator.generate();
            Map<String, String> queryParams = new HashMap<>();
            queryParams.put("state", STATE.getValue());
            queryParams.put("error", OAuth2Error.ACCESS_DENIED_CODE);
            queryParams.put("error_description", OAuth2Error.ACCESS_DENIED.getDescription());
            var noSessionEntity =
                    crossBrowserOrchestrationService.generateEntityForMismatchInClientSessionId(
                            queryParams, cookieClientSessionID, ORCH_SESSION_ITEM);

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

        // QualityGateRegressionTest
        @Test
        void itShouldReturnEmptyIfClientSessionIdInCookieMatchesStateValue()
                throws NoSessionException {
            when(crossBrowserStorageService.getClientSessionId(STATE))
                    .thenReturn(Optional.of(CLIENT_SESSION_ID));
            when(orchClientSessionService.getClientSession(CLIENT_SESSION_ID))
                    .thenReturn(Optional.of(generateOrchClientSession()));

            Map<String, String> queryParams = new HashMap<>();
            queryParams.put("state", STATE.getValue());
            queryParams.put("error", OAuth2Error.ACCESS_DENIED_CODE);
            queryParams.put("error_description", OAuth2Error.ACCESS_DENIED.getDescription());
            var noSessionEntity =
                    crossBrowserOrchestrationService.generateEntityForMismatchInClientSessionId(
                            queryParams, CLIENT_SESSION_ID, ORCH_SESSION_ITEM);

            assertTrue(noSessionEntity.isEmpty());
        }

        // QualityGateRegressionTest
        @Test
        void itShouldThrowIfThereIsNoClientSessionIdAssociatedWithStateValue() {
            when(crossBrowserStorageService.getClientSessionId(STATE)).thenReturn(Optional.empty());
            when(orchClientSessionService.getClientSession(CLIENT_SESSION_ID))
                    .thenReturn(Optional.of(generateOrchClientSession()));

            Map<String, String> queryParams = new HashMap<>();
            queryParams.put("error", OAuth2Error.ACCESS_DENIED_CODE);
            queryParams.put("error_description", OAuth2Error.ACCESS_DENIED.getDescription());
            queryParams.put("state", STATE.getValue());

            assertThrows(
                    NoSessionException.class,
                    () ->
                            crossBrowserOrchestrationService
                                    .generateEntityForMismatchInClientSessionId(
                                            queryParams, CLIENT_SESSION_ID, ORCH_SESSION_ITEM));
        }

        // QualityGateRegressionTest
        @Test
        void
                itShouldThrowIfThereIsAMismatchBetweenCookieAndStateAndClientSessionCannotBeRetrievedFromStateValue() {
            var clientSessionIdFromState = IdGenerator.generate();
            when(crossBrowserStorageService.getClientSessionId(STATE))
                    .thenReturn(Optional.of(clientSessionIdFromState));
            when(orchClientSessionService.getClientSession(clientSessionIdFromState))
                    .thenReturn(Optional.empty());

            Map<String, String> queryParams = new HashMap<>();
            queryParams.put("error", OAuth2Error.ACCESS_DENIED_CODE);
            queryParams.put("error_description", OAuth2Error.ACCESS_DENIED.getDescription());
            queryParams.put("state", STATE.getValue());

            assertThrows(
                    NoSessionException.class,
                    () ->
                            crossBrowserOrchestrationService
                                    .generateEntityForMismatchInClientSessionId(
                                            queryParams, CLIENT_SESSION_ID, ORCH_SESSION_ITEM));
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
