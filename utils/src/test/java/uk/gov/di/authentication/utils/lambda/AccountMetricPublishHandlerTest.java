package uk.gov.di.authentication.utils.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.ScheduledEvent;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.core.pagination.sync.SdkIterable;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbEnhancedClient;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.enhanced.dynamodb.model.PageIterable;
import software.amazon.awssdk.enhanced.dynamodb.model.ScanEnhancedRequest;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.DescribeTableRequest;
import software.amazon.awssdk.services.dynamodb.model.DescribeTableResponse;
import software.amazon.awssdk.services.dynamodb.model.GlobalSecondaryIndexDescription;
import software.amazon.awssdk.services.dynamodb.model.TableDescription;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.util.stream.Stream;

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
    private final DynamoDbEnhancedClient enhancedClient = mock(DynamoDbEnhancedClient.class);
    @SuppressWarnings("unchecked")
    private final DynamoDbTable<UserProfile> table = mock(DynamoDbTable.class);
    @SuppressWarnings("unchecked")
    private final PageIterable<UserProfile> pageIterable = mock(PageIterable.class);
    @SuppressWarnings("unchecked")
    private final SdkIterable<UserProfile> sdkIterable = mock(SdkIterable.class);

    private final AccountMetricPublishHandler handler =
            new AccountMetricPublishHandler(configurationService, client, enhancedClient, cloudwatchMetricsService);

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
        when(enhancedClient.<UserProfile>table(any(String.class), any())).thenReturn(table);
        when(table.scan(any(ScanEnhancedRequest.class))).thenReturn(pageIterable);
        when(pageIterable.items()).thenReturn(sdkIterable);
        when(sdkIterable.stream()).thenReturn(Stream.empty());

        handler.handleRequest(mock(ScheduledEvent.class), mock(Context.class));

        verify(cloudwatchMetricsService, times(1))
                .putEmbeddedValue("NumberOfAccounts", 5100, Map.of());
        verify(cloudwatchMetricsService, times(1))
                .putEmbeddedValue("NumberOfVerifiedAccounts", 5000, Map.of());
        verify(cloudwatchMetricsService, times(1))
                .putEmbeddedValue("NonUkPhoneNumbersVerifiedAccounts", 0L, Map.of());
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
        when(enhancedClient.<UserProfile>table(any(String.class), any())).thenReturn(table);
        when(table.scan(any(ScanEnhancedRequest.class))).thenReturn(pageIterable);
        when(pageIterable.items()).thenReturn(sdkIterable);
        when(sdkIterable.stream()).thenReturn(Stream.empty());

        assertThrows(
                NoSuchElementException.class,
                () -> handler.handleRequest(mock(ScheduledEvent.class), mock(Context.class)));

        verify(cloudwatchMetricsService, never()).putEmbeddedValue(any(), anyDouble(), any());
    }
}
