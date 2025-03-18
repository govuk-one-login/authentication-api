package uk.gov.di.orchestration.shared.utils;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import uk.gov.di.orchestration.shared.entity.ClientSession;
import uk.gov.di.orchestration.shared.entity.CredentialTrustLevel;
import uk.gov.di.orchestration.shared.entity.LevelOfConfidence;
import uk.gov.di.orchestration.shared.entity.OrchClientSessionItem;
import uk.gov.di.orchestration.shared.entity.VectorOfTrust;
import uk.gov.di.orchestration.shared.services.OrchClientSessionService;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.orchestration.shared.utils.ClientSessionMigrationUtils.areClientSessionsEqual;
import static uk.gov.di.orchestration.shared.utils.ClientSessionMigrationUtils.getOrchClientSessionWithRetryIfNotEqual;
import static uk.gov.di.orchestration.sharedtest.helper.Constants.CLIENT_SESSION_ID;

class ClientSessionMigrationUtilsTest {
    private static final Map<String, List<String>> AUTH_REQUEST_PARAMS =
            Map.of("testField", List.of("testValue"));
    private static final LocalDateTime CREATION_DATE =
            LocalDateTime.ofInstant(
                    Instant.parse("2025-02-19T14:19:43.590Z"), ZoneId.systemDefault());
    private static final List<VectorOfTrust> VTR_LIST =
            List.of(VectorOfTrust.of(CredentialTrustLevel.LOW_LEVEL, LevelOfConfidence.LOW_LEVEL));
    private static final String CLIENT_NAME = "test-client-name";
    private final OrchClientSessionService orchClientSessionService =
            mock(OrchClientSessionService.class);

    @Nested
    class AreClientSessionsEqual {
        @Test
        void shouldIdentifyClientSessionsAsEqual() {
            var clientSession =
                    new ClientSession(AUTH_REQUEST_PARAMS, CREATION_DATE, VTR_LIST, CLIENT_NAME);
            var orchClientSession =
                    new OrchClientSessionItem(
                            "test-client-session-id",
                            AUTH_REQUEST_PARAMS,
                            CREATION_DATE,
                            VTR_LIST,
                            CLIENT_NAME);

            assertTrue(areClientSessionsEqual(clientSession, orchClientSession));
        }

        @Test
        void shouldIdentifyClientSessionsAsEqualIfBothAreNull() {
            assertTrue(areClientSessionsEqual(null, null));
        }

        @Test
        void shouldIdentifyClientSessionsAsNotEqualWhenBothFieldsAreNotNull() {
            var clientSession =
                    new ClientSession(AUTH_REQUEST_PARAMS, CREATION_DATE, VTR_LIST, CLIENT_NAME);
            var orchClientSession =
                    new OrchClientSessionItem(
                            "test-client-session-id",
                            AUTH_REQUEST_PARAMS,
                            CREATION_DATE,
                            VTR_LIST,
                            "a-different-client-name");

            assertFalse(areClientSessionsEqual(clientSession, orchClientSession));
        }

        @Test
        void shouldIdentifyClientSessionsAsNotEqualWhenOneFieldIsNull() {
            var clientSession =
                    new ClientSession(AUTH_REQUEST_PARAMS, CREATION_DATE, VTR_LIST, CLIENT_NAME);
            var orchClientSession =
                    new OrchClientSessionItem(
                            "test-client-session-id",
                            AUTH_REQUEST_PARAMS,
                            CREATION_DATE,
                            VTR_LIST,
                            null);

            assertFalse(areClientSessionsEqual(clientSession, orchClientSession));
        }

        @Test
        void shouldIdentifyClientSessionsAsNotEqualWhenRedisClientSessionIsNull() {
            var orchClientSession =
                    new OrchClientSessionItem(
                            "test-client-session-id",
                            AUTH_REQUEST_PARAMS,
                            CREATION_DATE,
                            VTR_LIST,
                            CLIENT_NAME);

            assertFalse(areClientSessionsEqual(null, orchClientSession));
        }

        @Test
        void shouldIdentifyClientSessionsAsNotEqualWhenOrchClientSessionIsNull() {
            var clientSession =
                    new ClientSession(AUTH_REQUEST_PARAMS, CREATION_DATE, VTR_LIST, CLIENT_NAME);

            assertFalse(areClientSessionsEqual(clientSession, null));
        }

        @Test
        void shouldIdentifyClientSessionsAsNotEqualWhenMoreThanOneFieldIsDifferent() {
            var clientSession =
                    new ClientSession(AUTH_REQUEST_PARAMS, CREATION_DATE, VTR_LIST, CLIENT_NAME);
            var orchClientSession =
                    new OrchClientSessionItem(
                            "test-client-session-id",
                            Map.of(),
                            LocalDateTime.now(),
                            List.of(),
                            "different-client-name");

            assertFalse(areClientSessionsEqual(clientSession, orchClientSession));
        }
    }

    @Nested
    class RetryGetClientSession {
        LocalDateTime creationDate = LocalDateTime.now();
        ClientSession clientSession =
                new ClientSession(Map.of(), creationDate, List.of(), CLIENT_NAME);

        @Test
        void shouldRetryGetFromDynamoIfClientSessionsAreNotEqual() {
            OrchClientSessionItem oldClientSession =
                    new OrchClientSessionItem(
                            CLIENT_SESSION_ID,
                            Map.of(),
                            creationDate,
                            List.of(),
                            "a-different-client-name");
            OrchClientSessionItem latestClientSession =
                    new OrchClientSessionItem(
                            CLIENT_SESSION_ID, Map.of(), creationDate, List.of(), CLIENT_NAME);
            when(orchClientSessionService.getClientSession(CLIENT_SESSION_ID))
                    .thenReturn(Optional.of(oldClientSession));
            when(orchClientSessionService.forceGetClientSession(CLIENT_SESSION_ID))
                    .thenReturn(Optional.of(latestClientSession));

            var actualOrchClientSession =
                    getOrchClientSessionWithRetryIfNotEqual(
                            clientSession, CLIENT_SESSION_ID, orchClientSessionService);

            assertTrue(actualOrchClientSession.isPresent());
            assertEquals(latestClientSession, actualOrchClientSession.get());
            verify(orchClientSessionService).getClientSession(CLIENT_SESSION_ID);
            verify(orchClientSessionService).forceGetClientSession(CLIENT_SESSION_ID);
        }

        @Test
        void shouldNotRetryGetFromDynamoIfClientSessionsAreEqual() {
            OrchClientSessionItem orchClientSession =
                    new OrchClientSessionItem(
                            CLIENT_SESSION_ID, Map.of(), creationDate, List.of(), CLIENT_NAME);
            when(orchClientSessionService.getClientSession(CLIENT_SESSION_ID))
                    .thenReturn(Optional.of(orchClientSession));

            var actualOrchClientSession =
                    getOrchClientSessionWithRetryIfNotEqual(
                            clientSession, CLIENT_SESSION_ID, orchClientSessionService);

            assertTrue(actualOrchClientSession.isPresent());
            assertEquals(orchClientSession, actualOrchClientSession.get());
            verify(orchClientSessionService).getClientSession(CLIENT_SESSION_ID);
            verify(orchClientSessionService, never()).forceGetClientSession(CLIENT_SESSION_ID);
        }
    }
}
