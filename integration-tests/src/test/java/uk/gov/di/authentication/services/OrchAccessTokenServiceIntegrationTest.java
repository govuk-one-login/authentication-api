package uk.gov.di.authentication.services;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.orchestration.shared.entity.OrchAccessTokenItem;
import uk.gov.di.orchestration.shared.exceptions.OrchAccessTokenException;
import uk.gov.di.orchestration.sharedtest.extensions.OrchAccessTokenExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class OrchAccessTokenServiceIntegrationTest {
    private static final String CLIENT_AND_RP_PAIRWISE_ID = "test-clientId.rpPairwiseId";
    private static final String AUTH_CODE = "test-auth-code";
    private static final String TOKEN = "test-token";
    private static final String INTERNAL_PAIRWISE_SUBJECT_ID = "test-internal-pairwise-subject-id";
    private static final String CLIENT_SESSION_ID = "test-client-session-id";

    @RegisterExtension
    protected static final OrchAccessTokenExtension orchAccessTokenExtension =
            new OrchAccessTokenExtension();

    @Nested
    class SaveAccessToken {
        @Test
        void shouldSaveOrchAccessTokenWithAllFieldsSet() {
            orchAccessTokenExtension.saveAccessToken(
                    CLIENT_AND_RP_PAIRWISE_ID,
                    AUTH_CODE,
                    TOKEN,
                    INTERNAL_PAIRWISE_SUBJECT_ID,
                    CLIENT_SESSION_ID);
            var accessToken =
                    orchAccessTokenExtension.getAccessToken(CLIENT_AND_RP_PAIRWISE_ID, AUTH_CODE);

            assertTrue(accessToken.isPresent());
            assertOrchAccessTokenItemMatchesExpected(accessToken.get());
        }

        @Test
        void shouldThrowWhenFailingToSaveAccessToken() {
            assertThrows(
                    OrchAccessTokenException.class,
                    () -> orchAccessTokenExtension.saveAccessToken(null, null, null, null, null));
        }

        private static void assertOrchAccessTokenItemMatchesExpected(
                OrchAccessTokenItem orchAccessTokenItem) {
            assertEquals(CLIENT_AND_RP_PAIRWISE_ID, orchAccessTokenItem.getClientAndRpPairwiseId());
            assertEquals(TOKEN, orchAccessTokenItem.getToken());
            assertEquals(
                    INTERNAL_PAIRWISE_SUBJECT_ID,
                    orchAccessTokenItem.getInternalPairwiseSubjectId());
            assertEquals(CLIENT_SESSION_ID, orchAccessTokenItem.getClientSessionId());
            assertEquals(AUTH_CODE, orchAccessTokenItem.getAuthCode());
        }
    }

    @Nested
    class GetByClientAndRpPairwiseIdAndAuthCode {

        @Test
        void shouldReturnEmptyWhenNoAccessTokenExistsForClientAndRpPairwiseId() {
            orchAccessTokenExtension.saveAccessToken(
                    CLIENT_AND_RP_PAIRWISE_ID,
                    AUTH_CODE,
                    TOKEN,
                    INTERNAL_PAIRWISE_SUBJECT_ID,
                    CLIENT_SESSION_ID);
            var accessToken =
                    orchAccessTokenExtension.getAccessToken(
                            "unknown-clientId.rpPairwiseId", AUTH_CODE);
            assertTrue(accessToken.isEmpty());
        }

        @Test
        void shouldReturnEmptyWhenNoAccessTokenExistsForAuthCode() {
            orchAccessTokenExtension.saveAccessToken(
                    CLIENT_AND_RP_PAIRWISE_ID,
                    AUTH_CODE,
                    TOKEN,
                    INTERNAL_PAIRWISE_SUBJECT_ID,
                    CLIENT_SESSION_ID);
            var accessToken =
                    orchAccessTokenExtension.getAccessToken(
                            CLIENT_AND_RP_PAIRWISE_ID, "unknown-auth-code");
            assertTrue(accessToken.isEmpty());
        }
    }

    @Nested
    class GetByAuthCode {
        @Test
        void shouldReturnAccessTokenForAuthCode() {
            orchAccessTokenExtension.saveAccessToken(
                    CLIENT_AND_RP_PAIRWISE_ID,
                    AUTH_CODE,
                    TOKEN,
                    INTERNAL_PAIRWISE_SUBJECT_ID,
                    CLIENT_SESSION_ID);
            var accessToken = orchAccessTokenExtension.getAccessTokenForAuthCode(AUTH_CODE);
            assertTrue(accessToken.isPresent());
            assertEquals(CLIENT_AND_RP_PAIRWISE_ID, accessToken.get().getClientAndRpPairwiseId());
            assertEquals(AUTH_CODE, accessToken.get().getAuthCode());
            assertEquals(TOKEN, accessToken.get().getToken());
            assertEquals(
                    INTERNAL_PAIRWISE_SUBJECT_ID, accessToken.get().getInternalPairwiseSubjectId());
            assertEquals(CLIENT_SESSION_ID, accessToken.get().getClientSessionId());
        }

        @Test
        void shouldReturnEmptyWhenNoAccessTokenExistsForAuthCode() {
            orchAccessTokenExtension.saveAccessToken(
                    CLIENT_AND_RP_PAIRWISE_ID,
                    AUTH_CODE,
                    TOKEN,
                    INTERNAL_PAIRWISE_SUBJECT_ID,
                    CLIENT_SESSION_ID);
            var accessToken =
                    orchAccessTokenExtension.getAccessTokenForAuthCode("unknown auth code");
            assertTrue(accessToken.isEmpty());
        }
    }
}
