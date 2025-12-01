package uk.gov.di.orchestration.shared.services;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.enhanced.dynamodb.Key;
import software.amazon.awssdk.enhanced.dynamodb.model.GetItemEnhancedRequest;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.DynamoDbException;
import uk.gov.di.orchestration.shared.entity.OrchAccessTokenItem;
import uk.gov.di.orchestration.shared.exceptions.OrchAccessTokenException;
import uk.gov.di.orchestration.sharedtest.basetest.BaseDynamoServiceTest;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class OrchAccessTokenServiceTest extends BaseDynamoServiceTest<OrchAccessTokenItem> {

    private static final String CLIENT_AND_RP_PAIRWISE_ID = "test-clientId.rpPairwiseId";
    private static final String TOKEN = "test-token";
    private static final String INTERNAL_PAIRWISE_SUBJECT_ID = "test-internal-pairwise-subject-id";
    private static final String CLIENT_SESSION_ID = "test-client-session-id";
    private static final String AUTH_CODE = "test-auth-code";
    private static final String AUTH_CODE_INDEX = "AuthCodeIndex";
    private static final Instant CREATION_INSTANT = Instant.parse("2025-02-01T03:04:05.678Z");

    private final DynamoDbTable<OrchAccessTokenItem> table = mock(DynamoDbTable.class);
    private final DynamoDbClient dynamoDbClient = mock(DynamoDbClient.class);
    private OrchAccessTokenService orchAccessTokenService;

    @BeforeEach
    void setup() {
        when(configurationService.getAccessTokenExpiry()).thenReturn(3600L);
        orchAccessTokenService =
                new OrchAccessTokenService(
                        dynamoDbClient,
                        table,
                        configurationService,
                        Clock.fixed(CREATION_INSTANT, ZoneId.systemDefault()));
    }

    @Nested
    class StoreOrchAccessToken {
        @Test
        void shouldStoreAccessTokenSuccessfully() {
            orchAccessTokenService.saveAccessToken(
                    CLIENT_AND_RP_PAIRWISE_ID,
                    AUTH_CODE,
                    TOKEN,
                    INTERNAL_PAIRWISE_SUBJECT_ID,
                    CLIENT_SESSION_ID);

            var orchAccessTokenItemCaptor = ArgumentCaptor.forClass(OrchAccessTokenItem.class);
            verify(table).putItem(orchAccessTokenItemCaptor.capture());
            var capturedRequest = orchAccessTokenItemCaptor.getValue();

            assertOrchAccessTokenItemMatchesExpected(capturedRequest);
            assertTrue(capturedRequest.getTimeToLive() > CREATION_INSTANT.getEpochSecond());
        }

        @Test
        void shouldThrowWhenDynamoThrowsException() {
            doThrow(DynamoDbException.builder().message("Failed to put item in table").build())
                    .when(table)
                    .putItem(any(OrchAccessTokenItem.class));

            var exception =
                    assertThrows(
                            OrchAccessTokenException.class,
                            () ->
                                    orchAccessTokenService.saveAccessToken(
                                            CLIENT_AND_RP_PAIRWISE_ID,
                                            TOKEN,
                                            INTERNAL_PAIRWISE_SUBJECT_ID,
                                            CLIENT_SESSION_ID,
                                            AUTH_CODE));
            assertEquals("Failed to save Orch access token item to Dynamo", exception.getMessage());
        }
    }

    @Nested
    class GetOrchAccessTokenByClientAndRpPairwiseIdAndAuthCode {
        @Test
        void shouldGetAccessTokenSuccessfully() {
            var orchAccessTokenItem =
                    new OrchAccessTokenItem()
                            .withClientAndRpPairwiseId(CLIENT_AND_RP_PAIRWISE_ID)
                            .withToken(TOKEN)
                            .withInternalPairwiseSubjectId(INTERNAL_PAIRWISE_SUBJECT_ID)
                            .withClientSessionId(CLIENT_SESSION_ID)
                            .withAuthCode(AUTH_CODE);

            GetItemEnhancedRequest orchAccessTokenGetRequest =
                    GetItemEnhancedRequest.builder()
                            .key(
                                    Key.builder()
                                            .partitionValue(CLIENT_AND_RP_PAIRWISE_ID)
                                            .sortValue(AUTH_CODE)
                                            .build())
                            .consistentRead(true)
                            .build();
            when(table.getItem(orchAccessTokenGetRequest)).thenReturn(orchAccessTokenItem);

            var actualOrchAccessToken =
                    orchAccessTokenService.getAccessToken(CLIENT_AND_RP_PAIRWISE_ID, AUTH_CODE);

            assertTrue(actualOrchAccessToken.isPresent());
            assertOrchAccessTokenItemMatchesExpected(actualOrchAccessToken.get());
        }

        @Test
        void shouldReturnEmptyWhenNoAccessTokenForClientIdAndRpPairwiseId() {
            when(table.getItem(any(GetItemEnhancedRequest.class))).thenReturn(null);

            var actualOrchAccessToken =
                    orchAccessTokenService.getAccessToken(CLIENT_AND_RP_PAIRWISE_ID, AUTH_CODE);

            assertTrue(actualOrchAccessToken.isEmpty());
        }

        @Test
        void shouldThrowWhenDynamoThrowsException() {
            doThrow(DynamoDbException.builder().message("Failed to get item from table").build())
                    .when(table)
                    .getItem(any(GetItemEnhancedRequest.class));

            var exception =
                    assertThrows(
                            OrchAccessTokenException.class,
                            () ->
                                    orchAccessTokenService.getAccessToken(
                                            CLIENT_AND_RP_PAIRWISE_ID, AUTH_CODE));
            assertEquals("Failed to get Orch access token from Dynamo", exception.getMessage());
        }
    }

    @Nested
    class GetOrchAccessTokenByAuthCode {
        @Test
        void shouldGetAccessTokenSuccessfully() {
            var orchAccessTokenItem =
                    new OrchAccessTokenItem()
                            .withClientAndRpPairwiseId(CLIENT_AND_RP_PAIRWISE_ID)
                            .withAuthCode(AUTH_CODE)
                            .withToken(TOKEN)
                            .withInternalPairwiseSubjectId(INTERNAL_PAIRWISE_SUBJECT_ID)
                            .withClientSessionId(CLIENT_SESSION_ID);

            var spyService = spy(orchAccessTokenService);
            doReturn(List.of(orchAccessTokenItem))
                    .when(spyService)
                    .queryIndex(AUTH_CODE_INDEX, AUTH_CODE);

            var actualOrchAccessToken = spyService.getAccessTokenForAuthCode(AUTH_CODE);

            assertTrue(actualOrchAccessToken.isPresent());
            assertOrchAccessTokenItemMatchesExpected(actualOrchAccessToken.get());
        }

        @Test
        void shouldReturnEmptyWhenNoAccessTokenForAuthCode() {
            var spyService = spy(orchAccessTokenService);
            doReturn(List.of()).when(spyService).queryIndex(AUTH_CODE_INDEX, AUTH_CODE);

            var actualOrchAccessToken = spyService.getAccessTokenForAuthCode(AUTH_CODE);

            assertTrue(actualOrchAccessToken.isEmpty());
        }

        @Test
        void shouldThrowWhenDynamoThrowsException() {
            var spyService = spy(orchAccessTokenService);
            doThrow(DynamoDbException.class)
                    .when(spyService)
                    .queryIndex("authCode-index", AUTH_CODE);

            var exception =
                    assertThrows(
                            OrchAccessTokenException.class,
                            () -> orchAccessTokenService.getAccessTokenForAuthCode(AUTH_CODE));
            assertEquals("Failed to get Orch access token from Dynamo", exception.getMessage());
        }
    }

    @Nested
    class GetOrchAccessTokenByClientAndRpPairwiseIdAndTokenValue {
        @Test
        void shouldGetAccessTokenSuccessfully() {
            var orchAccessTokenItem =
                    new OrchAccessTokenItem()
                            .withClientAndRpPairwiseId(CLIENT_AND_RP_PAIRWISE_ID)
                            .withAuthCode(AUTH_CODE)
                            .withToken(TOKEN)
                            .withInternalPairwiseSubjectId(INTERNAL_PAIRWISE_SUBJECT_ID)
                            .withClientSessionId(CLIENT_SESSION_ID);

            var spyService = spy(orchAccessTokenService);
            doReturn(Stream.of(orchAccessTokenItem))
                    .when(spyService)
                    .queryTableStream(CLIENT_AND_RP_PAIRWISE_ID);

            var actualOrchAccessToken =
                    spyService.getAccessTokenForClientAndRpPairwiseIdAndTokenValue(
                            CLIENT_AND_RP_PAIRWISE_ID, TOKEN);

            assertTrue(actualOrchAccessToken.isPresent());
            assertOrchAccessTokenItemMatchesExpected(actualOrchAccessToken.get());
        }

        @Test
        void shouldReturnEmptyWhenNoMatchForTokenValue() {
            var orchAccessTokenItem =
                    new OrchAccessTokenItem()
                            .withClientAndRpPairwiseId(CLIENT_AND_RP_PAIRWISE_ID)
                            .withAuthCode(AUTH_CODE)
                            .withToken("different-token-value")
                            .withInternalPairwiseSubjectId(INTERNAL_PAIRWISE_SUBJECT_ID)
                            .withClientSessionId(CLIENT_SESSION_ID);

            var spyService = spy(orchAccessTokenService);
            doReturn(Stream.of(orchAccessTokenItem))
                    .when(spyService)
                    .queryTableStream(CLIENT_AND_RP_PAIRWISE_ID);

            var actualOrchAccessToken =
                    spyService.getAccessTokenForClientAndRpPairwiseIdAndTokenValue(
                            CLIENT_AND_RP_PAIRWISE_ID, TOKEN);

            assertTrue(actualOrchAccessToken.isEmpty());
        }

        @Test
        void shouldThrowWhenDynamoThrowsException() {
            var spyService = spy(orchAccessTokenService);
            doThrow(DynamoDbException.class)
                    .when(spyService)
                    .queryTableStream(CLIENT_AND_RP_PAIRWISE_ID);

            var exception =
                    assertThrows(
                            OrchAccessTokenException.class,
                            () ->
                                    orchAccessTokenService
                                            .getAccessTokenForClientAndRpPairwiseIdAndTokenValue(
                                                    CLIENT_AND_RP_PAIRWISE_ID, TOKEN));
            assertEquals("Failed to get Orch access token from Dynamo", exception.getMessage());
        }
    }

    @Nested
    class UpdatingTtl {
        @Test
        void shouldGetAccessTokensWithoutTtlInBatchesSuccessfully() {
            var spyService = spy(orchAccessTokenService);

            var allTokensSegment1 = createOrchAccessTokensWithOrWithoutTtl(1, 19);
            var allTokensSegment2 = createOrchAccessTokensWithOrWithoutTtl(2, 2);

            doReturn(allTokensSegment1.stream()).when(spyService).scanTableSegment(0, 2);
            doReturn(allTokensSegment2.stream()).when(spyService).scanTableSegment(1, 2);

            var capturedBatches = new ArrayList<List<OrchAccessTokenItem>>();
            spyService.processAccessTokensWithoutTtlInBatches(10, 2, 100, capturedBatches::add);

            assertEquals(
                    3,
                    capturedBatches.size()); // 2 batches from first segment, 1 from second segment
            var allItems = capturedBatches.stream().flatMap(List::stream).toList();
            assertEquals(21, allItems.size());
            assertTrue(allItems.stream().allMatch(item -> item.getTimeToLive() == 0));
        }

        @Test
        void shouldStopProcessingWhenMaxTokensReached() {
            var spyService = spy(orchAccessTokenService);

            var allTokensSegment1 = createOrchAccessTokensWithOrWithoutTtl(0, 50);
            var allTokensSegment2 = createOrchAccessTokensWithOrWithoutTtl(0, 50);

            doReturn(allTokensSegment1.stream()).when(spyService).scanTableSegment(0, 2);
            doReturn(allTokensSegment2.stream()).when(spyService).scanTableSegment(1, 2);

            var capturedBatches = new ArrayList<List<OrchAccessTokenItem>>();
            spyService.processAccessTokensWithoutTtlInBatches(10, 2, 25, capturedBatches::add);

            // Count items that actually completed processing
            var completedItems = capturedBatches.stream().flatMap(List::stream).toList();

            assertTrue(completedItems.size() <= 35, "should not exceed maxTokens + batch size");
            assertTrue(completedItems.size() >= 25, "should process at least maxTokens");
        }

        @Test
        void shouldBatchWriteSuccessfully() {
            var spyService = spy(orchAccessTokenService);

            var tokensToUpdate = createOrchAccessTokensWithOrWithoutTtl(0, 5);

            var expectedTtl = CREATION_INSTANT.getEpochSecond();

            doNothing().when(spyService).batchPut(any());
            spyService.updateAccessTokensTtlToNow(tokensToUpdate);

            tokensToUpdate.forEach(item -> assertEquals(expectedTtl, item.getTimeToLive()));
            verify(spyService).batchPut(tokensToUpdate);
        }

        List<OrchAccessTokenItem> createOrchAccessTokensWithOrWithoutTtl(
                int withTtl, int withoutTtl) {
            return Stream.concat(
                            IntStream.range(0, withTtl)
                                    .mapToObj(i -> createToken("test-" + i, 1234567890)),
                            IntStream.range(withTtl, withTtl + withoutTtl)
                                    .mapToObj(i -> createToken("test-" + i, 0)))
                    .toList();
        }

        private OrchAccessTokenItem createToken(String id, long ttl) {
            return new OrchAccessTokenItem()
                    .withClientAndRpPairwiseId(id)
                    .withAuthCode(id)
                    .withToken(id)
                    .withInternalPairwiseSubjectId(id)
                    .withClientSessionId(id)
                    .withTimeToLive(ttl);
        }
    }

    private void assertOrchAccessTokenItemMatchesExpected(OrchAccessTokenItem orchAccessTokenItem) {
        assertEquals(CLIENT_AND_RP_PAIRWISE_ID, orchAccessTokenItem.getClientAndRpPairwiseId());
        assertEquals(TOKEN, orchAccessTokenItem.getToken());
        assertEquals(
                INTERNAL_PAIRWISE_SUBJECT_ID, orchAccessTokenItem.getInternalPairwiseSubjectId());
        assertEquals(CLIENT_SESSION_ID, orchAccessTokenItem.getClientSessionId());
        assertEquals(AUTH_CODE, orchAccessTokenItem.getAuthCode());
    }
}
