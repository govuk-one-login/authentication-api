package uk.gov.di.authentication.utils.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.BatchWriteItemRequest;
import software.amazon.awssdk.services.dynamodb.model.BatchWriteItemResponse;
import software.amazon.awssdk.services.dynamodb.model.ScanRequest;
import software.amazon.awssdk.services.dynamodb.model.ScanResponse;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class InternationalSendCountDeleteHandlerTest {

    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final DynamoDbClient client = mock(DynamoDbClient.class);

    private InternationalSendCountDeleteHandler createHandler() {
        when(configurationService.getEnvironment()).thenReturn("test");
        when(client.batchWriteItem(any(BatchWriteItemRequest.class)))
                .thenReturn(BatchWriteItemResponse.builder().build());
        return new InternationalSendCountDeleteHandler(configurationService, client);
    }

    private void mockScanResponse(List<Map<String, AttributeValue>> items) {
        when(client.scan(any(ScanRequest.class)))
                .thenReturn(
                        ScanResponse.builder()
                                .items(items)
                                .count(0)
                                .lastEvaluatedKey(Collections.emptyMap())
                                .build());
    }

    @Test
    void shouldHandleEmptyTable() {
        var handler = createHandler();
        mockScanResponse(Collections.emptyList());

        handler.handleRequest(null, mock(Context.class));

        verify(client, never()).batchWriteItem(any(BatchWriteItemRequest.class));
    }

    @Test
    void shouldDeleteAllItemsInSingleBatch() {
        var handler = createHandler();
        var items =
                List.of(
                        Map.of("PhoneNumber", AttributeValue.builder().s("+441234567890").build()),
                        Map.of("PhoneNumber", AttributeValue.builder().s("+441234567891").build()));

        mockScanResponse(items);

        handler.handleRequest(null, mock(Context.class));

        verify(client, times(1)).batchWriteItem(any(BatchWriteItemRequest.class));
        verify(client)
                .batchWriteItem(
                        argThat(
                                (BatchWriteItemRequest r) ->
                                        r.requestItems()
                                                        .get("test-international-sms-send-count")
                                                        .size()
                                                == 2));
    }

    @Test
    void shouldFlushBatchAt25Items() {
        var handler = createHandler();
        List<Map<String, AttributeValue>> items = new ArrayList<>();
        for (int i = 0; i < 26; i++) {
            items.add(
                    Map.of(
                            "PhoneNumber",
                            AttributeValue.builder()
                                    .s("+44123456" + String.format("%04d", i))
                                    .build()));
        }

        mockScanResponse(items);

        handler.handleRequest(null, mock(Context.class));

        verify(client, times(2)).batchWriteItem(any(BatchWriteItemRequest.class));
    }

    @Test
    void shouldHandlePaginatedScan() {
        var handler = createHandler();
        var lastKey = Map.of("PhoneNumber", AttributeValue.builder().s("+441234567890").build());

        when(client.scan(any(ScanRequest.class)))
                // delete scan page 1
                .thenReturn(
                        ScanResponse.builder()
                                .items(
                                        List.of(
                                                Map.of(
                                                        "PhoneNumber",
                                                        AttributeValue.builder()
                                                                .s("+441234567890")
                                                                .build())))
                                .lastEvaluatedKey(lastKey)
                                .build())
                // delete scan page 2
                .thenReturn(
                        ScanResponse.builder()
                                .items(
                                        List.of(
                                                Map.of(
                                                        "PhoneNumber",
                                                        AttributeValue.builder()
                                                                .s("+441234567891")
                                                                .build())))
                                .lastEvaluatedKey(Collections.emptyMap())
                                .build())
                // post-deletion count scan
                .thenReturn(
                        ScanResponse.builder()
                                .items(Collections.emptyList())
                                .count(0)
                                .lastEvaluatedKey(Collections.emptyMap())
                                .build());

        handler.handleRequest(null, mock(Context.class));

        verify(client, times(2)).batchWriteItem(any(BatchWriteItemRequest.class));
        verify(client, times(3)).scan(any(ScanRequest.class));
    }
}
