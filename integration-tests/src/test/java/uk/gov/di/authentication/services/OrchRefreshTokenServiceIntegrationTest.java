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

    @RegisterExtension
    protected static final OrchRefreshTokenExtension orchRefreshTokenExtension =
            new OrchRefreshTokenExtension();

    @Test
    void shouldStoreOrchRefreshTokenWithAllFieldsSet() {
        orchRefreshTokenExtension.saveRefreshToken(
                JWT_ID, INTERNAL_PAIRWISE_SUBJECT_ID, TOKEN, AUTH_CODE);

        var refreshToken = orchRefreshTokenExtension.getRefreshToken(JWT_ID);

        assertTrue(refreshToken.isPresent());
        assertEquals(JWT_ID, refreshToken.get().getJwtId());
        assertEquals(
                INTERNAL_PAIRWISE_SUBJECT_ID, refreshToken.get().getInternalPairwiseSubjectId());
        assertEquals(TOKEN, refreshToken.get().getToken());
        assertEquals(AUTH_CODE, refreshToken.get().getAuthCode());
        assertTrue(refreshToken.get().getIsUsed());
    }

    @Test
    void shouldReturnEmptyOptionalWhenNoRefreshTokenExistsForJwtId() {
        orchRefreshTokenExtension.saveRefreshToken(
                JWT_ID, INTERNAL_PAIRWISE_SUBJECT_ID, TOKEN, AUTH_CODE);
        var refreshToken = orchRefreshTokenExtension.getRefreshToken("different-jwt-id");
        assertTrue(refreshToken.isEmpty());
    }

    @Test
    void shouldReturnEmptyOptionalWhenRefreshTokenForJwtIdIsAlreadyUsed() {
        orchRefreshTokenExtension.saveRefreshToken(
                JWT_ID, INTERNAL_PAIRWISE_SUBJECT_ID, TOKEN, AUTH_CODE);

        var refreshToken = orchRefreshTokenExtension.getRefreshToken("different-jwt-id");
        assertTrue(refreshToken.isEmpty());
    }

    @Test
    void shouldReturnRefreshTokenForAuthCode() {
        orchRefreshTokenExtension.saveRefreshToken(
                JWT_ID, INTERNAL_PAIRWISE_SUBJECT_ID, TOKEN, AUTH_CODE);
        var refreshToken = orchRefreshTokenExtension.getRefreshTokenForAuthCode(AUTH_CODE);
        assertTrue(refreshToken.isPresent());
        assertEquals(JWT_ID, refreshToken.get().getJwtId());
        assertEquals(
                INTERNAL_PAIRWISE_SUBJECT_ID, refreshToken.get().getInternalPairwiseSubjectId());
        assertEquals(TOKEN, refreshToken.get().getToken());
        assertEquals(AUTH_CODE, refreshToken.get().getAuthCode());
        assertFalse(refreshToken.get().getIsUsed());
    }

    @Test
    void shouldReturnEmptyOptionalWhenNoRefreshTokenExistsForAuthCode() {
        orchRefreshTokenExtension.saveRefreshToken(
                JWT_ID, INTERNAL_PAIRWISE_SUBJECT_ID, TOKEN, AUTH_CODE);
        var refreshToken =
                orchRefreshTokenExtension.getRefreshTokenForAuthCode("different-auth-code");
        assertTrue(refreshToken.isEmpty());
    }

    @Test
    void shouldThrowWhenFailingToSaveRefreshToken() {
        assertThrows(
                OrchRefreshTokenException.class,
                () -> orchRefreshTokenExtension.saveRefreshToken(null, null, null, null));
    }
}
