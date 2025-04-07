package uk.gov.di.orchestration.shared.utils;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import uk.gov.di.orchestration.shared.entity.ClientSession;
import uk.gov.di.orchestration.shared.entity.CredentialTrustLevel;
import uk.gov.di.orchestration.shared.entity.LevelOfConfidence;
import uk.gov.di.orchestration.shared.entity.OrchClientSessionItem;
import uk.gov.di.orchestration.shared.entity.VectorOfTrust;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.orchestration.shared.utils.ClientSessionMigrationUtils.areClientSessionsEqual;

class ClientSessionMigrationUtilsTest {
    private static final Map<String, List<String>> AUTH_REQUEST_PARAMS =
            Map.of("testField", List.of("testValue"));
    private static final LocalDateTime CREATION_DATE =
            LocalDateTime.ofInstant(
                    Instant.parse("2025-02-19T14:19:43.590Z"), ZoneId.systemDefault());
    private static final List<VectorOfTrust> VTR_LIST =
            List.of(VectorOfTrust.of(CredentialTrustLevel.LOW_LEVEL, LevelOfConfidence.LOW_LEVEL));
    private static final String CLIENT_NAME = "test-client-name";

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
}
