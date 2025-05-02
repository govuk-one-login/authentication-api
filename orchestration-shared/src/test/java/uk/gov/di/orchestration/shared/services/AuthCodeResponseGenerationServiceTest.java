package uk.gov.di.orchestration.shared.services;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.orchestration.shared.entity.OrchSessionItem;
import uk.gov.di.orchestration.shared.entity.Session;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.orchestration.shared.entity.MFAMethodType.AUTH_APP;
import static uk.gov.di.orchestration.shared.entity.OrchSessionItem.AccountState.NEW;
import static uk.gov.di.orchestration.sharedtest.helper.Constants.CLIENT_NAME;
import static uk.gov.di.orchestration.sharedtest.helper.Constants.CLIENT_SESSION_ID;
import static uk.gov.di.orchestration.sharedtest.helper.Constants.ENVIRONMENT;
import static uk.gov.di.orchestration.sharedtest.helper.Constants.SESSION_ID;

class AuthCodeResponseGenerationServiceTest {

    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final OrchSessionService orchSessionService = mock(OrchSessionService.class);
    private final SessionService sessionService = mock(SessionService.class);
    private OrchSessionItem orchSession;
    private Session session;

    private AuthCodeResponseGenerationService authCodeResponseGenerationService;

    @BeforeEach
    void setup() {
        when(configurationService.getEnvironment()).thenReturn(ENVIRONMENT);
        orchSession =
                new OrchSessionItem(SESSION_ID)
                        .withAccountState(NEW)
                        .withVerifiedMfaMethodType(AUTH_APP.toString());
        session = new Session();
        authCodeResponseGenerationService =
                new AuthCodeResponseGenerationService(configurationService);
    }

    @Test
    void getDimensionsReturnsMapOfValues() {
        Map<String, String> expectedValues =
                new HashMap<>(
                        Map.of(
                                "Account",
                                NEW.name(),
                                "Environment",
                                configurationService.getEnvironment(),
                                "Client",
                                CLIENT_SESSION_ID,
                                "IsTest",
                                Boolean.toString(Boolean.FALSE),
                                "IsDocApp",
                                Boolean.toString(Boolean.FALSE),
                                "ClientName",
                                CLIENT_NAME,
                                "MfaMethod",
                                AUTH_APP.toString()));

        var actualValues =
                authCodeResponseGenerationService.getDimensions(
                        orchSession, CLIENT_NAME, CLIENT_SESSION_ID, false, false);
        assertEquals(expectedValues, actualValues);
    }

    @Test
    void saveSessionUpdatesNonDocAppSessionWithAuthenticatedAndAccountState() {
        authCodeResponseGenerationService.saveSession(
                false, sessionService, session, SESSION_ID, orchSessionService, orchSession);

        verify(sessionService)
                .storeOrUpdateSession(
                        argThat(
                                s ->
                                        s.isAuthenticated()
                                                && s.isNewAccount()
                                                        == Session.AccountState.EXISTING),
                        eq(SESSION_ID));
        verify(orchSessionService)
                .updateSession(
                        argThat(
                                s ->
                                        s.getAuthenticated()
                                                && s.getIsNewAccount()
                                                        == OrchSessionItem.AccountState.EXISTING));
    }

    @Test
    void saveSessionUpdatesDocAppSessionWithDocAppState() {
        authCodeResponseGenerationService.saveSession(
                true, sessionService, session, SESSION_ID, orchSessionService, orchSession);

        verify(sessionService)
                .storeOrUpdateSession(
                        argThat(
                                s ->
                                        s.isNewAccount()
                                                == Session.AccountState.EXISTING_DOC_APP_JOURNEY),
                        eq(SESSION_ID));
        verify(orchSessionService)
                .updateSession(
                        argThat(
                                s ->
                                        s.getIsNewAccount()
                                                == OrchSessionItem.AccountState
                                                        .EXISTING_DOC_APP_JOURNEY));
    }
}
