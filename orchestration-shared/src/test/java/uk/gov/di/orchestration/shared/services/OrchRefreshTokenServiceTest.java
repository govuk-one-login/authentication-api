package uk.gov.di.orchestration.shared.services;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.enhanced.dynamodb.model.GetItemEnhancedRequest;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.DynamoDbException;
import uk.gov.di.orchestration.shared.entity.OrchRefreshTokenItem;
import uk.gov.di.orchestration.shared.exceptions.OrchRefreshTokenException;
import uk.gov.di.orchestration.shared.lambda.LambdaTimer;
import uk.gov.di.orchestration.sharedtest.basetest.BaseDynamoServiceTest;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class OrchRefreshTokenServiceTest extends BaseDynamoServiceTest<OrchRefreshTokenItem> {

    private static final String JWT_ID = "test-jwt-id";
    private static final String INTERNAL_PAIRWISE_SUBJECT_ID = "test-internal-pairwise-subject-id";
    private static final String TOKEN = "test-token";
    private static final String AUTH_CODE = "test-auth-code";
    private static final String AUTH_CODE_INDEX = "AuthCodeIndex";
    private static final Instant CREATION_INSTANT = Instant.parse("2025-02-01T03:04:05.678Z");

    private final DynamoDbTable<OrchRefreshTokenItem> table = mock(DynamoDbTable.class);
    private final DynamoDbClient dynamoDbClient = mock(DynamoDbClient.class);
    private OrchRefreshTokenService orchRefreshTokenService;

    @BeforeEach
    void setup() {
        when(configurationService.getRefreshTokenExpiry()).thenReturn(3600L);
        orchRefreshTokenService =
                new OrchRefreshTokenService(
                        dynamoDbClient,
                        table,
                        configurationService,
                        Clock.fixed(CREATION_INSTANT, ZoneId.systemDefault()));
    }

    @Test
    void shouldStoreOrchRefreshTokenItem() {
        orchRefreshTokenService.saveRefreshToken(
                JWT_ID, INTERNAL_PAIRWISE_SUBJECT_ID, TOKEN, AUTH_CODE);

        var orchRefreshTokenItemCaptor = ArgumentCaptor.forClass(OrchRefreshTokenItem.class);
        verify(table).putItem(orchRefreshTokenItemCaptor.capture());
        var refreshTokenFromCapturedRequest = orchRefreshTokenItemCaptor.getValue();

        assertEquals(JWT_ID, refreshTokenFromCapturedRequest.getJwtId());
        assertEquals(
                INTERNAL_PAIRWISE_SUBJECT_ID,
                refreshTokenFromCapturedRequest.getInternalPairwiseSubjectId());
        assertEquals(TOKEN, refreshTokenFromCapturedRequest.getToken());
        assertEquals(AUTH_CODE, refreshTokenFromCapturedRequest.getAuthCode());
        assertFalse(refreshTokenFromCapturedRequest.getIsUsed());
        assertEquals(
                CREATION_INSTANT.getEpochSecond() + 3600L,
                refreshTokenFromCapturedRequest.getTimeToLive());
    }

    @Test
    void shouldThrowWhenFailsToStoreOrchRefreshToken() {
        doThrow(DynamoDbException.builder().message("Failed to put item in table").build())
                .when(table)
                .putItem(any(OrchRefreshTokenItem.class));

        var exception =
                assertThrows(
                        OrchRefreshTokenException.class,
                        () ->
                                orchRefreshTokenService.saveRefreshToken(
                                        JWT_ID, INTERNAL_PAIRWISE_SUBJECT_ID, TOKEN, AUTH_CODE));
        assertEquals("Failed to save Orch refresh token item to Dynamo", exception.getMessage());
    }

    @Test
    void shouldGetOrchRefreshTokenForJwtId() {
        var orchRefreshTokenItem =
                new OrchRefreshTokenItem()
                        .withJwtId(JWT_ID)
                        .withInternalPairwiseSubjectId(INTERNAL_PAIRWISE_SUBJECT_ID)
                        .withToken(TOKEN)
                        .withAuthCode(AUTH_CODE);

        when(table.getItem(getRequestFor(JWT_ID))).thenReturn(orchRefreshTokenItem);

        var actualOrchRefreshToken = orchRefreshTokenService.getRefreshToken(JWT_ID);

        assertTrue(actualOrchRefreshToken.isPresent());
        assertEquals(JWT_ID, orchRefreshTokenItem.getJwtId());
        assertEquals(
                INTERNAL_PAIRWISE_SUBJECT_ID, orchRefreshTokenItem.getInternalPairwiseSubjectId());
        assertEquals(TOKEN, orchRefreshTokenItem.getToken());
        assertEquals(AUTH_CODE, orchRefreshTokenItem.getAuthCode());
        assertTrue(orchRefreshTokenItem.getIsUsed());
    }

    @Test
    void shouldReturnEmptyWhenNoRefreshTokenForJwtId() {
        when(table.getItem(any(GetItemEnhancedRequest.class))).thenReturn(null);

        var actualOrchRefreshToken = orchRefreshTokenService.getRefreshToken(JWT_ID);

        assertTrue(actualOrchRefreshToken.isEmpty());
    }

    @Test
    void shouldReturnEmptyWhenRefreshTokenIsAlreadyUsed() {
        var orchRefreshTokenItem =
                new OrchRefreshTokenItem()
                        .withJwtId(JWT_ID)
                        .withInternalPairwiseSubjectId(INTERNAL_PAIRWISE_SUBJECT_ID)
                        .withToken(TOKEN)
                        .withAuthCode(AUTH_CODE);
        orchRefreshTokenItem.setIsUsed(true);

        when(table.getItem(getRequestFor(JWT_ID))).thenReturn(orchRefreshTokenItem);

        var actualOrchRefreshToken = orchRefreshTokenService.getRefreshToken(JWT_ID);

        assertTrue(actualOrchRefreshToken.isEmpty());
    }

    @Test
    void shouldThrowWhenFailsToGetOrchRefreshToken() {
        doThrow(DynamoDbException.builder().message("Failed to get item from table").build())
                .when(table)
                .getItem(any(GetItemEnhancedRequest.class));

        var exception =
                assertThrows(
                        OrchRefreshTokenException.class,
                        () -> orchRefreshTokenService.getRefreshToken(JWT_ID));
        assertEquals("Failed to get Orch refresh token from Dynamo", exception.getMessage());
    }

    @Test
    void shouldGetOrchRefreshTokensForAuthCode() {
        var orchRefreshTokenItems =
                List.of(
                        new OrchRefreshTokenItem()
                                .withJwtId(JWT_ID)
                                .withInternalPairwiseSubjectId(INTERNAL_PAIRWISE_SUBJECT_ID)
                                .withToken(TOKEN)
                                .withAuthCode(AUTH_CODE)
                                .withIsUsed(false),
                        new OrchRefreshTokenItem()
                                .withJwtId("another-jwt-id")
                                .withInternalPairwiseSubjectId("another-internal-pairwise-id")
                                .withToken("another-token")
                                .withAuthCode(AUTH_CODE)
                                .withIsUsed(true));

        var spyService = spy(orchRefreshTokenService);
        doReturn(orchRefreshTokenItems).when(spyService).queryIndex(AUTH_CODE_INDEX, AUTH_CODE);

        var actualOrchRefreshTokens = spyService.getRefreshTokensForAuthCode(AUTH_CODE);

        assertEquals(2, actualOrchRefreshTokens.size());
        assertEquals(JWT_ID, orchRefreshTokenItems.get(0).getJwtId());
        assertEquals(
                INTERNAL_PAIRWISE_SUBJECT_ID,
                orchRefreshTokenItems.get(0).getInternalPairwiseSubjectId());
        assertEquals(TOKEN, orchRefreshTokenItems.get(0).getToken());
        assertEquals(AUTH_CODE, orchRefreshTokenItems.get(0).getAuthCode());
        assertFalse(orchRefreshTokenItems.get(0).getIsUsed());
        assertEquals("another-jwt-id", orchRefreshTokenItems.get(1).getJwtId());
        assertEquals(
                "another-internal-pairwise-id",
                orchRefreshTokenItems.get(1).getInternalPairwiseSubjectId());
        assertEquals("another-token", orchRefreshTokenItems.get(1).getToken());
        assertEquals(AUTH_CODE, orchRefreshTokenItems.get(1).getAuthCode());
        assertTrue(orchRefreshTokenItems.get(1).getIsUsed());
    }

    @Test
    void shouldReturnEmptyListWhenNoRefreshTokenForAuthCode() {
        var spyService = spy(orchRefreshTokenService);
        doReturn(List.of()).when(spyService).queryIndex(AUTH_CODE_INDEX, AUTH_CODE);

        var orchRefreshTokenItems = spyService.getRefreshTokensForAuthCode(AUTH_CODE);

        assertTrue(orchRefreshTokenItems.isEmpty());
    }

    @Test
    void shouldThrowWhenFailsToGetOrchRefreshTokenForAuthCode() {
        var spyService = spy(orchRefreshTokenService);
        doThrow(RuntimeException.class).when(spyService).queryIndex(AUTH_CODE_INDEX, AUTH_CODE);

        var exception =
                assertThrows(
                        OrchRefreshTokenException.class,
                        () -> orchRefreshTokenService.getRefreshTokensForAuthCode(AUTH_CODE));
        assertEquals(
                "Failed to get Orch refresh tokens from Dynamo for auth code",
                exception.getMessage());
    }

    @Nested
    class UpdateTokenTtl {
        private final LambdaTimer mockLambdaTimer = mock(LambdaTimer.class);
        private final List<List<OrchRefreshTokenItem>> batchesProcessed = new ArrayList<>();
        private OrchRefreshTokenService spyService;

        @BeforeEach
        void setup() {
            when(mockLambdaTimer.hasTimeRemaining(anyLong())).thenReturn(true);
            batchesProcessed.clear();
            spyService = spy(orchRefreshTokenService);
        }

        @Test
        void shouldNotUpdateTokensIfNoTokensFoundWithTtlOfZero() {
            var token1 = tokenWithTtl(123L);
            var token2 = tokenWithTtl(456L);
            var token3 = tokenWithTtl(789L);
            doReturn(Stream.of(token1, token2, token3)).when(spyService).scanTable();

            spyService.processRefreshTokensWithoutTtlSequentially(
                    mockLambdaTimer, 100, batchesProcessed::add);

            assertTrue(batchesProcessed.isEmpty());
        }

        @Test
        void shouldUpdateTtlOfTokensIfTokenFoundWithTtlOfZero() {
            var token1 = tokenWithoutTtl();
            var token2 = tokenWithTtl(456L);
            var token3 = tokenWithoutTtl();
            doReturn(Stream.of(token1, token2, token3)).when(spyService).scanTable();

            spyService.processRefreshTokensWithoutTtlSequentially(
                    mockLambdaTimer, 100, batchesProcessed::add);

            assertThat(batchesProcessed, contains(List.of(token1, token3)));
        }

        @Test
        void shouldStopUpdatingTokensIfLambdaIsNearTimeout() {
            when(mockLambdaTimer.hasTimeRemaining(anyLong())).thenReturn(true).thenReturn(false);
            var token1 = tokenWithoutTtl();
            var token2 = tokenWithTtl(456L);
            var token3 = tokenWithoutTtl();
            doReturn(Stream.of(token1, token2, token3)).when(spyService).scanTable();

            spyService.processRefreshTokensWithoutTtlSequentially(
                    mockLambdaTimer, 100, batchesProcessed::add);

            assertThat(batchesProcessed, contains(List.of(token1)));
        }

        @Test
        void shouldUpdateTokensInBatchesWhenReadBatchSizeIsMet() {
            var token1 = tokenWithoutTtl();
            var token2 = tokenWithTtl(456L);
            var token3 = tokenWithoutTtl();
            var token4 = tokenWithoutTtl();
            doReturn(Stream.of(token1, token2, token3, token4)).when(spyService).scanTable();

            spyService.processRefreshTokensWithoutTtlSequentially(
                    mockLambdaTimer, 2, batchesProcessed::add);

            assertThat(batchesProcessed, contains(List.of(token1, token3), List.of(token4)));
        }

        @Test
        void shouldSetTokenTtlToNowUsingMethod() {
            var mockNow = Instant.parse("2026-01-14T13:30:00Z");
            fixCurrentTime(mockNow);
            spyService = spy(orchRefreshTokenService);
            doNothing().when(spyService).batchPut(anyList());
            var token = tokenWithoutTtl();

            spyService.updateRefreshTokenBatchTtlToNow(List.of(token));
            verify(spyService)
                    .batchPut(
                            argThat(
                                    list ->
                                            list.size() == 1
                                                    && list.get(0).getTimeToLive()
                                                            == mockNow.getEpochSecond()));
        }

        private void fixCurrentTime(Instant time) {
            orchRefreshTokenService =
                    new OrchRefreshTokenService(
                            dynamoDbClient,
                            table,
                            configurationService,
                            Clock.fixed(time, ZoneOffset.UTC));
        }

        private OrchRefreshTokenItem tokenWithoutTtl() {
            return tokenWithTtl(0L);
        }

        private OrchRefreshTokenItem tokenWithTtl(long ttl) {
            return new OrchRefreshTokenItem()
                    .withToken("test-token")
                    .withAuthCode("test-auth-code")
                    .withJwtId("test-jwt-id")
                    .withIsUsed(false)
                    .withTimeToLive(ttl);
        }
    }
}
