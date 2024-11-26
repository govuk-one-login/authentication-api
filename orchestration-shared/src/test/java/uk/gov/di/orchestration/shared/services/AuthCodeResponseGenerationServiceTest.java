package uk.gov.di.orchestration.shared.services;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import uk.gov.di.orchestration.shared.entity.ClientSession;
import uk.gov.di.orchestration.shared.entity.CredentialTrustLevel;
import uk.gov.di.orchestration.shared.entity.LevelOfConfidence;
import uk.gov.di.orchestration.shared.entity.OrchSessionItem;
import uk.gov.di.orchestration.shared.entity.Session;
import uk.gov.di.orchestration.shared.entity.VectorOfTrust;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
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
    private final DynamoService dynamoService = mock(DynamoService.class);
    private final OrchSessionService orchSessionService = mock(OrchSessionService.class);
    private final SessionService sessionService = mock(SessionService.class);
    private OrchSessionItem orchSession;
    private Session session;
    private ClientSession clientSession;

    private AuthCodeResponseGenerationService authCodeResponseGenerationService;
    private static final CredentialTrustLevel lowestCredentialTrustLevel =
            CredentialTrustLevel.LOW_LEVEL;

    @BeforeEach
    void setup() {
        when(configurationService.getEnvironment()).thenReturn(ENVIRONMENT);
        orchSession =
                new OrchSessionItem(SESSION_ID)
                        .withAccountState(NEW)
                        .withVerifiedMfaMethodType(AUTH_APP.toString());
        session = new Session(SESSION_ID);
        authCodeResponseGenerationService =
                new AuthCodeResponseGenerationService(configurationService, dynamoService);
        clientSession =
                new ClientSession(
                        new HashMap<>(),
                        LocalDateTime.MIN,
                        List.of(
                                VectorOfTrust.of(
                                        lowestCredentialTrustLevel, LevelOfConfidence.LOW_LEVEL)),
                        CLIENT_NAME);
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
                        orchSession, clientSession, CLIENT_SESSION_ID, false, false);
        assertEquals(expectedValues, actualValues);
    }

    @Test
    void saveSessionUpdatesNonDocAppSessionWithAuthenticatedAndAccountState() {
        authCodeResponseGenerationService.saveSession(
                false, sessionService, session, orchSessionService, orchSession, clientSession);

        verify(sessionService)
                .storeOrUpdateSession(
                        argThat(
                                s ->
                                        s.isAuthenticated()
                                                && s.isNewAccount()
                                                        == Session.AccountState.EXISTING));
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
                true, sessionService, session, orchSessionService, orchSession, clientSession);

        verify(sessionService)
                .storeOrUpdateSession(
                        argThat(
                                s ->
                                        s.isNewAccount()
                                                == Session.AccountState.EXISTING_DOC_APP_JOURNEY));
        verify(orchSessionService)
                .updateSession(
                        argThat(
                                s ->
                                        s.getIsNewAccount()
                                                == OrchSessionItem.AccountState
                                                        .EXISTING_DOC_APP_JOURNEY));
    }

    @Nested
    class CurrentCredentialStrength {

        @BeforeEach
        void setup() {
            when(configurationService.isCurrentCredentialStrengthInOrchSessionEnabled())
                    .thenReturn(true);
        }

        @Test
        void
                shouldSaveSessionWithCurrentCredentialStrengthWhenIsCurrentCredentialStrengthInOrchSessionFlagEnabled() {
            authCodeResponseGenerationService.saveSession(
                    true, sessionService, session, orchSessionService, orchSession, clientSession);
            var orchSessionCaptor = ArgumentCaptor.forClass(OrchSessionItem.class);
            verify(orchSessionService, times(1)).updateSession(orchSessionCaptor.capture());
            assertThat(
                    orchSessionCaptor.getAllValues().get(0).getCurrentCredentialStrength(),
                    equalTo(lowestCredentialTrustLevel));
        }

        private static Stream<Arguments> currentCredentialStrengthParams() {
            return Stream.of(
                    Arguments.of( // 1
                            null,
                            CredentialTrustLevel.MEDIUM_LEVEL,
                            CredentialTrustLevel.MEDIUM_LEVEL),
                    Arguments.of( // 2
                            CredentialTrustLevel.LOW_LEVEL,
                            CredentialTrustLevel.MEDIUM_LEVEL,
                            CredentialTrustLevel.MEDIUM_LEVEL),
                    Arguments.of( // 3
                            CredentialTrustLevel.MEDIUM_LEVEL,
                            CredentialTrustLevel.MEDIUM_LEVEL,
                            CredentialTrustLevel.MEDIUM_LEVEL),
                    Arguments.of( // 4
                            null, CredentialTrustLevel.LOW_LEVEL, CredentialTrustLevel.LOW_LEVEL),
                    Arguments.of( // 5
                            CredentialTrustLevel.LOW_LEVEL,
                            CredentialTrustLevel.LOW_LEVEL,
                            CredentialTrustLevel.LOW_LEVEL),
                    Arguments.of( // 6
                            CredentialTrustLevel.MEDIUM_LEVEL,
                            CredentialTrustLevel.LOW_LEVEL,
                            CredentialTrustLevel.MEDIUM_LEVEL));
        }

        @ParameterizedTest
        @MethodSource("currentCredentialStrengthParams")
        void shouldSaveSesionWithCurrentCredentialStrengthWhenSessionValuesAreCorrect(
                CredentialTrustLevel orchSessionCurrentCredentialStrength,
                CredentialTrustLevel credentialTrustLevel,
                CredentialTrustLevel correctCurrentCredentialStrengthSet) {
            var clientSessionWithCredentialTrust =
                    createSessionWithCredentialTrust(credentialTrustLevel);
            var orchSessionWithCurentCredentialStrength =
                    new OrchSessionItem(SESSION_ID)
                            .withAccountState(NEW)
                            .withVerifiedMfaMethodType(AUTH_APP.toString())
                            .withCurrentCredentialStrength(orchSessionCurrentCredentialStrength);

            authCodeResponseGenerationService.saveSession(
                    true,
                    sessionService,
                    session,
                    orchSessionService,
                    orchSessionWithCurentCredentialStrength,
                    clientSessionWithCredentialTrust);
            var orchSessionCaptor = ArgumentCaptor.forClass(OrchSessionItem.class);
            verify(orchSessionService, times(1)).updateSession(orchSessionCaptor.capture());
            assertThat(
                    orchSessionCaptor.getAllValues().get(0).getCurrentCredentialStrength(),
                    equalTo(correctCurrentCredentialStrengthSet));
        }

        private ClientSession createSessionWithCredentialTrust(
                CredentialTrustLevel credentialTrustLevel) {
            return clientSession =
                    new ClientSession(
                            new HashMap<>(),
                            LocalDateTime.MIN,
                            List.of(
                                    VectorOfTrust.of(
                                            credentialTrustLevel, LevelOfConfidence.LOW_LEVEL)),
                            CLIENT_NAME);
        }
    }
}
