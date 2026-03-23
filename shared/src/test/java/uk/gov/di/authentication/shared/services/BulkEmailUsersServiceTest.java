package uk.gov.di.authentication.shared.services;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.QueryRequest;
import software.amazon.awssdk.services.dynamodb.model.QueryResponse;
import uk.gov.di.authentication.shared.entity.BulkEmailStatus;
import uk.gov.di.authentication.shared.entity.BulkEmailUser;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class BulkEmailUsersServiceTest {

    @SuppressWarnings("unchecked")
    private final DynamoDbTable<BulkEmailUser> dynamoTable = mock(DynamoDbTable.class);

    private final DynamoDbClient dynamoDbClient = mock(DynamoDbClient.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private BulkEmailUsersService bulkEmailUsersService;

    @BeforeEach
    void setUp() {
        when(configurationService.getEnvironment()).thenReturn("test");
        bulkEmailUsersService =
                new BulkEmailUsersService(dynamoTable, dynamoDbClient, configurationService);
    }

    @Nested
    class GetNSubjectIdsByStatus {

        @Test
        void shouldReturnSubjectIdsAndLastEvaluatedKey() {
            var lastKey = Map.of("SubjectID", AttributeValue.fromS("user-2"));
            var response =
                    QueryResponse.builder()
                            .items(
                                    List.of(
                                            Map.of("SubjectID", AttributeValue.fromS("user-1")),
                                            Map.of("SubjectID", AttributeValue.fromS("user-2"))))
                            .lastEvaluatedKey(lastKey)
                            .build();
            when(dynamoDbClient.query(any(QueryRequest.class))).thenReturn(response);

            var result =
                    bulkEmailUsersService.getNSubjectIdsByStatus(10, BulkEmailStatus.PENDING, null);

            assertEquals(List.of("user-1", "user-2"), result.subjectIds());
            assertEquals(lastKey, result.lastEvaluatedKey());
        }

        @Test
        void shouldPassExclusiveStartKey() {
            var startKey = Map.of("SubjectID", AttributeValue.fromS("start-user"));
            var response = QueryResponse.builder().items(List.of()).build();
            when(dynamoDbClient.query(any(QueryRequest.class))).thenReturn(response);

            bulkEmailUsersService.getNSubjectIdsByStatus(10, BulkEmailStatus.PENDING, startKey);

            verify(dynamoDbClient)
                    .query(
                            org.mockito.ArgumentMatchers.argThat(
                                    (QueryRequest req) ->
                                            req.exclusiveStartKey() != null
                                                    && req.exclusiveStartKey().equals(startKey)));
        }

        @Test
        void shouldReturnEmptyLastEvaluatedKeyWhenNoMoreResults() {
            var response =
                    QueryResponse.builder().items(List.of()).lastEvaluatedKey(Map.of()).build();
            when(dynamoDbClient.query(any(QueryRequest.class))).thenReturn(response);

            var result =
                    bulkEmailUsersService.getNSubjectIdsByStatus(10, BulkEmailStatus.PENDING, null);

            assertTrue(result.subjectIds().isEmpty());
            assertTrue(result.lastEvaluatedKey().isEmpty());
        }
    }

    @Nested
    class GetNSubjectIdsByDeliveryReceiptStatus {

        @Test
        void shouldReturnSubjectIdsAndLastEvaluatedKey() {
            var lastKey = Map.of("SubjectID", AttributeValue.fromS("user-2"));
            var response =
                    QueryResponse.builder()
                            .items(
                                    List.of(
                                            Map.of("SubjectID", AttributeValue.fromS("user-1")),
                                            Map.of("SubjectID", AttributeValue.fromS("user-2"))))
                            .lastEvaluatedKey(lastKey)
                            .build();
            when(dynamoDbClient.query(any(QueryRequest.class))).thenReturn(response);

            var result =
                    bulkEmailUsersService.getNSubjectIdsByDeliveryReceiptStatus(
                            10, "temporary-failure", null);

            assertEquals(List.of("user-1", "user-2"), result.subjectIds());
            assertEquals(lastKey, result.lastEvaluatedKey());
        }

        @Test
        void shouldPassExclusiveStartKey() {
            var startKey = Map.of("SubjectID", AttributeValue.fromS("start-user"));
            var response = QueryResponse.builder().items(List.of()).build();
            when(dynamoDbClient.query(any(QueryRequest.class))).thenReturn(response);

            bulkEmailUsersService.getNSubjectIdsByDeliveryReceiptStatus(
                    10, "temporary-failure", startKey);

            verify(dynamoDbClient)
                    .query(
                            org.mockito.ArgumentMatchers.argThat(
                                    (QueryRequest req) ->
                                            req.exclusiveStartKey() != null
                                                    && req.exclusiveStartKey().equals(startKey)));
        }
    }
}
