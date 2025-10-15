package uk.gov.di.orchestration.shared.services;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.enhanced.dynamodb.Key;
import software.amazon.awssdk.enhanced.dynamodb.model.GetItemEnhancedRequest;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.DynamoDbException;
import uk.gov.di.orchestration.shared.entity.OrchAccessTokenItem;
import uk.gov.di.orchestration.shared.exceptions.OrchAccessTokenException;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class OrchAccessTokenServiceTest {

    private static final String CLIENT_AND_RP_PAIRWISE_ID = "test-clientId.rpPairwiseId";
    private static final String TOKEN = "test-token";
    private static final String INTERNAL_PAIRWISE_SUBJECT_ID = "test-internal-pairwise-subject-id";
    private static final String CLIENT_SESSION_ID = "test-client-session-id";
    private static final String AUTH_CODE = "test-auth-code";
    private static final String AUTH_CODE_INDEX = "AuthCodeIndex";

    private final DynamoDbTable<OrchAccessTokenItem> table = mock(DynamoDbTable.class);
    private final DynamoDbClient dynamoDbClient = mock(DynamoDbClient.class);
    private OrchAccessTokenService orchAccessTokenService;

    @BeforeEach
    void setup() {
        orchAccessTokenService = new OrchAccessTokenService(dynamoDbClient, table);
    }

    @Test
    void shouldStoreOrchAccessTokenItem() {
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
    }

    @Test
    void shouldThrowWhenFailsToStoreOrchAccessToken() {
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

    @Test
    void shouldGetOrchAccessTokenForClientAndRpPairwiseIdAndAuthCode() {
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
    void shouldThrowWhenFailsToGetOrchAccessToken() {
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

    @Test
    void shouldGetOrchAccessTokenForAuthCode() {
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
    void shouldThrowWhenFailsToGetOrchAccessTokenForAuthCode() {
        var spyService = spy(orchAccessTokenService);
        doThrow(RuntimeException.class).when(spyService).queryIndex("authCode-index", AUTH_CODE);

        var exception =
                assertThrows(
                        OrchAccessTokenException.class,
                        () -> orchAccessTokenService.getAccessTokenForAuthCode(AUTH_CODE));
        assertEquals("Failed to get Orch access token from Dynamo", exception.getMessage());
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
