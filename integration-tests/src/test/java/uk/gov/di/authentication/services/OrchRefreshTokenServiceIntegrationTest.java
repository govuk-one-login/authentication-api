package uk.gov.di.authentication.services;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.orchestration.shared.exceptions.OrchRefreshTokenException;
import uk.gov.di.orchestration.sharedtest.extensions.OrchRefreshTokenExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class OrchRefreshTokenServiceIntegrationTest {
    private static final String JWT_ID = "test-jwt-id";
    private static final String INTERNAL_PAIRWISE_SUBJECT_ID = "test-internal-pairwise-subject-id";
    private static final String TOKEN = "test-token";
    private static final String AUTH_CODE = "test-auth-code";
    private static final String CLIENT_SESSION_ID = "test-client-session-id";

    @RegisterExtension
    protected static final OrchRefreshTokenExtension orchRefreshTokenExtension =
            new OrchRefreshTokenExtension();

    @Test
    void shouldStoreOrchRefreshTokenWithAllFieldsSet() {
        orchRefreshTokenExtension.saveRefreshToken(
                JWT_ID, INTERNAL_PAIRWISE_SUBJECT_ID, TOKEN, AUTH_CODE, CLIENT_SESSION_ID);

        var refreshToken = orchRefreshTokenExtension.getRefreshToken(JWT_ID);

        assertTrue(refreshToken.isPresent());
        assertEquals(JWT_ID, refreshToken.get().getJwtId());
        assertEquals(
                INTERNAL_PAIRWISE_SUBJECT_ID, refreshToken.get().getInternalPairwiseSubjectId());
        assertEquals(TOKEN, refreshToken.get().getToken());
        assertEquals(AUTH_CODE, refreshToken.get().getAuthCode());
        assertEquals(CLIENT_SESSION_ID, refreshToken.get().getClientSessionId());
        // getting the token causes it to be marked as used
        assertTrue(refreshToken.get().getIsUsed());
    }

    @Test
    void shouldReturnEmptyOptionalWhenNoRefreshTokenExistsForJwtId() {
        orchRefreshTokenExtension.saveRefreshToken(
                JWT_ID, INTERNAL_PAIRWISE_SUBJECT_ID, TOKEN, AUTH_CODE, CLIENT_SESSION_ID);
        var refreshToken = orchRefreshTokenExtension.getRefreshToken("different-jwt-id");
        assertTrue(refreshToken.isEmpty());
    }

    @Test
    void shouldReturnEmptyOptionalWhenRefreshTokenForJwtIdIsAlreadyUsed() {
        orchRefreshTokenExtension.saveRefreshToken(
                JWT_ID, INTERNAL_PAIRWISE_SUBJECT_ID, TOKEN, AUTH_CODE, CLIENT_SESSION_ID);
        var refreshToken = orchRefreshTokenExtension.getRefreshToken(JWT_ID);
        assertTrue(refreshToken.isPresent());

        refreshToken = orchRefreshTokenExtension.getRefreshToken(JWT_ID);
        assertTrue(refreshToken.isEmpty());
    }

    @Test
    void shouldReturnRefreshTokensForAuthCode() {
        orchRefreshTokenExtension.saveRefreshToken(
                JWT_ID, INTERNAL_PAIRWISE_SUBJECT_ID, TOKEN, AUTH_CODE, CLIENT_SESSION_ID);
        orchRefreshTokenExtension.saveRefreshToken(
                "another-jwt-id",
                "another-internal-pairwise-id",
                "another-token",
                AUTH_CODE,
                "another-csid");
        var refreshTokens = orchRefreshTokenExtension.getRefreshTokensForAuthCode(AUTH_CODE);
        assertEquals(2, refreshTokens.size());

        var firstRefreshToken =
                refreshTokens.stream().filter(token -> token.getJwtId().equals(JWT_ID)).findFirst();
        var secondRefreshToken =
                refreshTokens.stream()
                        .filter(token -> token.getJwtId().equals("another-jwt-id"))
                        .findFirst();
        assertTrue(firstRefreshToken.isPresent());
        assertTrue(secondRefreshToken.isPresent());

        assertEquals(TOKEN, firstRefreshToken.get().getToken());
        assertEquals(
                INTERNAL_PAIRWISE_SUBJECT_ID,
                firstRefreshToken.get().getInternalPairwiseSubjectId());
        assertEquals(AUTH_CODE, firstRefreshToken.get().getAuthCode());
        assertFalse(firstRefreshToken.get().getIsUsed());
        assertEquals("another-token", secondRefreshToken.get().getToken());
        assertEquals(
                "another-internal-pairwise-id",
                secondRefreshToken.get().getInternalPairwiseSubjectId());
        assertEquals("another-csid", secondRefreshToken.get().getClientSessionId());
        assertEquals(AUTH_CODE, secondRefreshToken.get().getAuthCode());
        assertFalse(secondRefreshToken.get().getIsUsed());
    }

    @Test
    void shouldReturnEmptyListWhenNoRefreshTokenExistsForAuthCode() {
        orchRefreshTokenExtension.saveRefreshToken(
                JWT_ID, INTERNAL_PAIRWISE_SUBJECT_ID, TOKEN, AUTH_CODE, CLIENT_SESSION_ID);
        var refreshTokens =
                orchRefreshTokenExtension.getRefreshTokensForAuthCode("different-auth-code");
        assertTrue(refreshTokens.isEmpty());
    }

    @Test
    void shouldThrowWhenFailingToSaveRefreshToken() {
        assertThrows(
                OrchRefreshTokenException.class,
                () -> orchRefreshTokenExtension.saveRefreshToken(null, null, null, null, null));
    }
}
