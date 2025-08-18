package uk.gov.di.authentication.services;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.orchestration.shared.entity.AuthCodeExchangeData;
import uk.gov.di.orchestration.sharedtest.extensions.OrchAuthCodeExtension;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;

import static java.time.Clock.fixed;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class OrchAuthCodeServiceIntegrationTest {
    private static final String CLIENT_ID = "test-client-id";
    private static final String CLIENT_SESSION_ID = "test-client-session-id";
    private static final String EMAIL = "test-email";
    private static final long AUTH_TIME = 12345L;

    @RegisterExtension
    protected static final OrchAuthCodeExtension orchAuthCodeExtension =
            new OrchAuthCodeExtension();

    private static final String INTERNAL_PAIRWISE_SUBJECT_ID = "internal-pairwise-subject-id";

    @BeforeEach
    void setup() {
        orchAuthCodeExtension.setClock(Clock.systemUTC());
    }

    @Test
    void shouldStoreOrchAuthCodeExchangeDataAgainstAuthCodeWithAllFieldsSet() {
        var storedOrchAuthCodeItem =
                orchAuthCodeExtension.generateAndSaveAuthorisationCode(
                        CLIENT_ID,
                        CLIENT_SESSION_ID,
                        EMAIL,
                        AUTH_TIME,
                        INTERNAL_PAIRWISE_SUBJECT_ID);

        var authCode = storedOrchAuthCodeItem.getValue();
        var exchangeData = orchAuthCodeExtension.getExchangeDataForCode(authCode);

        assertTrue(exchangeData.isPresent());

        AuthCodeExchangeData expected =
                new AuthCodeExchangeData()
                        .withClientId(CLIENT_ID)
                        .withClientSessionId(CLIENT_SESSION_ID)
                        .withEmail(EMAIL)
                        .withAuthTime(AUTH_TIME)
                        .withInternalPairwiseSubjectId(INTERNAL_PAIRWISE_SUBJECT_ID);

        assertEquals(expected.getClientId(), exchangeData.get().getClientId());
        assertEquals(expected.getClientSessionId(), exchangeData.get().getClientSessionId());
        assertEquals(expected.getEmail(), exchangeData.get().getEmail());
        assertEquals(expected.getAuthTime(), exchangeData.get().getAuthTime());
        assertEquals(
                expected.getInternalPairwiseSubjectId(),
                exchangeData.get().getInternalPairwiseSubjectId());
    }

    @Test
    void shouldReturnEmptyOptionalWhenOrchAuthCodeItemWithAuthCodeDoesNotExist() {
        var exchangeData = orchAuthCodeExtension.getExchangeDataForCode("an-unknown-auth-code");

        assertTrue(exchangeData.isEmpty());
    }

    @Test
    void shouldReturnEmptyOptionalWhenOrchAuthCodeItemExistsButIsMarkedAsUsed() {
        var authCode =
                orchAuthCodeExtension.generateAndSaveAuthorisationCode(
                        CLIENT_ID,
                        CLIENT_SESSION_ID,
                        EMAIL,
                        AUTH_TIME,
                        INTERNAL_PAIRWISE_SUBJECT_ID);

        // Retrieve to mark auth code as "used".
        var exchangeDataFirstRetrieval =
                orchAuthCodeExtension.getExchangeDataForCode(authCode.getValue());

        // Retrieve again to check that the auth code has been marked as "used".
        var exchangeDataSecondRetrieval =
                orchAuthCodeExtension.getExchangeDataForCode(authCode.getValue());

        assertTrue(exchangeDataFirstRetrieval.isPresent());
        assertTrue(exchangeDataSecondRetrieval.isEmpty());
    }

    @Test
    void shouldReturnEmptyOptionalWhenOrchAuthCodeItemExistsButTimeToLiveExpired() {
        fixTime(Instant.parse("2025-01-02T01:00:00.000Z"));
        var authCode =
                orchAuthCodeExtension.generateAndSaveAuthorisationCode(
                        CLIENT_ID,
                        CLIENT_SESSION_ID,
                        EMAIL,
                        AUTH_TIME,
                        INTERNAL_PAIRWISE_SUBJECT_ID);

        // Default expiry is 5 minutes (300 seconds)
        fixTime(Instant.parse("2025-01-02T01:05:00.000Z"));
        var exchangeData = orchAuthCodeExtension.getExchangeDataForCode(authCode.getValue());

        assertTrue(exchangeData.isEmpty());
    }

    private static void fixTime(Instant time) {
        orchAuthCodeExtension.setClock(fixed(time, ZoneId.systemDefault()));
    }
}
