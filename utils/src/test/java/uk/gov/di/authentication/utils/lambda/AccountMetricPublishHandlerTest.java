package uk.gov.di.authentication.utils.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.ScheduledEvent;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.DescribeTableRequest;
import software.amazon.awssdk.services.dynamodb.model.DescribeTableResponse;
import software.amazon.awssdk.services.dynamodb.model.GlobalSecondaryIndexDescription;
import software.amazon.awssdk.services.dynamodb.model.TableDescription;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.util.Map;
import java.util.NoSuchElementException;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyDouble;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AccountMetricPublishHandlerTest {

    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final CloudwatchMetricsService cloudwatchMetricsService =
            mock(CloudwatchMetricsService.class);
    private final DynamoDbClient client = mock(DynamoDbClient.class);

    private final AccountMetricPublishHandler handler =
            new AccountMetricPublishHandler(configurationService, client, cloudwatchMetricsService);

    @Test
    void shouldPublishMetrics() {
        when(configurationService.getEnvironment()).thenReturn("test");
        when(client.describeTable(
                        DescribeTableRequest.builder().tableName("test-user-profile").build()))
                .thenReturn(
                        DescribeTableResponse.builder()
                                .table(
                                        TableDescription.builder()
                                                .globalSecondaryIndexes(
                                                        GlobalSecondaryIndexDescription.builder()
                                                                .indexName("VerifiedAccountIndex")
                                                                .itemCount(5000l)
                                                                .build(),
                                                        GlobalSecondaryIndexDescription.builder()
                                                                .indexName("AnotherIndex")
                                                                .itemCount(3000l)
                                                                .build())
                                                .itemCount(5100l)
                                                .build())
                                .build());

        handler.handleRequest(mock(ScheduledEvent.class), mock(Context.class));

        verify(cloudwatchMetricsService, times(1))
                .putEmbeddedValue("NumberOfAccounts", 5100, Map.of());
        verify(cloudwatchMetricsService, times(1))
                .putEmbeddedValue("NumberOfVerifiedAccounts", 5000, Map.of());
    }

    @Test
    void shouldNotPublishMetricsIfIndexNotFound() {
        when(configurationService.getEnvironment()).thenReturn("test");
        when(client.describeTable(
                        DescribeTableRequest.builder().tableName("test-user-profile").build()))
                .thenReturn(
                        DescribeTableResponse.builder()
                                .table(
                                        TableDescription.builder()
                                                .globalSecondaryIndexes(
                                                        GlobalSecondaryIndexDescription.builder()
                                                                .indexName("AnotherIndex")
                                                                .itemCount(3000l)
                                                                .build())
                                                .itemCount(5100l)
                                                .build())
                                .build());

        assertThrows(
                NoSuchElementException.class,
                () -> handler.handleRequest(mock(ScheduledEvent.class), mock(Context.class)));

        verify(cloudwatchMetricsService, never()).putEmbeddedValue(any(), anyDouble(), any());
    }
}
