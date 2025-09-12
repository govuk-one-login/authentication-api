package uk.gov.di.authentication.services;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.orchestration.shared.exceptions.OrchAccessTokenException;
import uk.gov.di.orchestration.sharedtest.extensions.OrchAccessTokenExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class OrchAccessTokenServiceIntegrationTest {
    private static final String CLIENT_ID = "test-client-id";
    private static final String RP_PAIRWISE_ID = "test-rp-pairwise-id";
    private static final String TOKEN = "test-token";
    private static final String INTERNAL_PAIRWISE_SUBJECT_ID = "test-internal-pairwise-subject-id";
    private static final String CLIENT_SESSION_ID = "test-client-session-id";
    private static final String AUTH_CODE = "test-auth-code";

    @RegisterExtension
    protected static final OrchAccessTokenExtension orchAccessTokenExtension =
            new OrchAccessTokenExtension();

    @Test
    void shouldStoreOrchAccessTokenWithAllFieldsSet() {
        orchAccessTokenExtension.saveAccessToken(
                CLIENT_ID,
                RP_PAIRWISE_ID,
                TOKEN,
                INTERNAL_PAIRWISE_SUBJECT_ID,
                CLIENT_SESSION_ID,
                AUTH_CODE);
        var accessToken = orchAccessTokenExtension.getAccessToken(CLIENT_ID, RP_PAIRWISE_ID);

        assertTrue(accessToken.isPresent());
        assertEquals(CLIENT_ID, accessToken.get().getClientId());
        assertEquals(RP_PAIRWISE_ID, accessToken.get().getRpPairwiseId());
        assertEquals(CLIENT_SESSION_ID, accessToken.get().getClientSessionId());
        assertEquals(TOKEN, accessToken.get().getToken());
        assertEquals(
                INTERNAL_PAIRWISE_SUBJECT_ID, accessToken.get().getInternalPairwiseSubjectId());
        assertEquals(AUTH_CODE, accessToken.get().getAuthCode());
    }

    @Test
    void shouldReturnEmptyOptionalWhenNoAccessTokenExistsForClientId() {
        orchAccessTokenExtension.saveAccessToken(
                CLIENT_ID,
                RP_PAIRWISE_ID,
                TOKEN,
                INTERNAL_PAIRWISE_SUBJECT_ID,
                CLIENT_SESSION_ID,
                AUTH_CODE);
        var accessToken =
                orchAccessTokenExtension.getAccessToken("unknown client id", RP_PAIRWISE_ID);
        assertTrue(accessToken.isEmpty());
    }

    @Test
    void shouldReturnEmptyOptionalWhenNoAccessTokenExistsForRpPairwiseId() {
        orchAccessTokenExtension.saveAccessToken(
                CLIENT_ID,
                RP_PAIRWISE_ID,
                TOKEN,
                INTERNAL_PAIRWISE_SUBJECT_ID,
                CLIENT_SESSION_ID,
                AUTH_CODE);
        var accessToken =
                orchAccessTokenExtension.getAccessToken(CLIENT_ID, "unknown rp pairwise id");
        assertTrue(accessToken.isEmpty());
    }

    @Test
    void shouldReturnAccessTokenForAuthCode() {
        orchAccessTokenExtension.saveAccessToken(
                CLIENT_ID,
                RP_PAIRWISE_ID,
                TOKEN,
                INTERNAL_PAIRWISE_SUBJECT_ID,
                CLIENT_SESSION_ID,
                AUTH_CODE);
        var accessToken = orchAccessTokenExtension.getAccessTokenForAuthCode(AUTH_CODE);
        assertTrue(accessToken.isPresent());
        assertEquals(CLIENT_ID, accessToken.get().getClientId());
        assertEquals(RP_PAIRWISE_ID, accessToken.get().getRpPairwiseId());
        assertEquals(CLIENT_SESSION_ID, accessToken.get().getClientSessionId());
        assertEquals(TOKEN, accessToken.get().getToken());
        assertEquals(
                INTERNAL_PAIRWISE_SUBJECT_ID, accessToken.get().getInternalPairwiseSubjectId());
        assertEquals(AUTH_CODE, accessToken.get().getAuthCode());
    }

    @Test
    void shouldReturnEmptyOptionalWhenNoAccessTokenExistsForAuthCode() {
        orchAccessTokenExtension.saveAccessToken(
                CLIENT_ID,
                RP_PAIRWISE_ID,
                TOKEN,
                INTERNAL_PAIRWISE_SUBJECT_ID,
                CLIENT_SESSION_ID,
                AUTH_CODE);
        var accessToken = orchAccessTokenExtension.getAccessTokenForAuthCode("unknown auth code");
        assertTrue(accessToken.isEmpty());
    }

    @Test
    void shouldThrowWhenFailingToSaveAccessToken() {
        assertThrows(
                OrchAccessTokenException.class,
                () -> orchAccessTokenExtension.saveAccessToken(null, null, null, null, null, null));
    }
}
