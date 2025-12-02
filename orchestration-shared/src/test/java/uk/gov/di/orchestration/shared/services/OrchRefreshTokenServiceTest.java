package uk.gov.di.orchestration.shared.services;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.enhanced.dynamodb.model.GetItemEnhancedRequest;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.DynamoDbException;
import uk.gov.di.orchestration.shared.entity.OrchRefreshTokenItem;
import uk.gov.di.orchestration.shared.exceptions.OrchRefreshTokenException;
import uk.gov.di.orchestration.sharedtest.basetest.BaseDynamoServiceTest;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
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
}
