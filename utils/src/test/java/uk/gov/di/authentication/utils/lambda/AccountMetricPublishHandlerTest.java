package uk.gov.di.authentication.utils.lambda;

import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.model.DescribeTableResult;
import com.amazonaws.services.dynamodbv2.model.GlobalSecondaryIndexDescription;
import com.amazonaws.services.dynamodbv2.model.TableDescription;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.ScheduledEvent;
import org.junit.jupiter.api.Test;
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
    private final AmazonDynamoDB client = mock(AmazonDynamoDB.class);

    private final AccountMetricPublishHandler handler =
            new AccountMetricPublishHandler(configurationService, client, cloudwatchMetricsService);

    @Test
    void shouldPublishMetrics() {
        when(configurationService.getEnvironment()).thenReturn("test");
        when(client.describeTable("test-user-profile"))
                .thenReturn(
                        new DescribeTableResult()
                                .withTable(
                                        new TableDescription()
                                                .withGlobalSecondaryIndexes(
                                                        new GlobalSecondaryIndexDescription()
                                                                .withIndexName(
                                                                        "VerifiedAccountIndex")
                                                                .withItemCount(5000l),
                                                        new GlobalSecondaryIndexDescription()
                                                                .withIndexName("AnotherIndex")
                                                                .withItemCount(3000l))
                                                .withItemCount(5100l)));

        handler.handleRequest(mock(ScheduledEvent.class), mock(Context.class));

        verify(cloudwatchMetricsService, times(1))
                .putEmbeddedValue("NumberOfAccounts", 5100, Map.of());
        verify(cloudwatchMetricsService, times(1))
                .putEmbeddedValue("NumberOfVerifiedAccounts", 5000, Map.of());
    }

    @Test
    void shouldNotPublishMetricsIfIndexNotFound() {
        when(configurationService.getEnvironment()).thenReturn("test");
        when(client.describeTable("test-user-profile"))
                .thenReturn(
                        new DescribeTableResult()
                                .withTable(
                                        new TableDescription()
                                                .withGlobalSecondaryIndexes(
                                                        new GlobalSecondaryIndexDescription()
                                                                .withIndexName("AnotherIndex")
                                                                .withItemCount(3000l))
                                                .withItemCount(5100l)));

        assertThrows(
                NoSuchElementException.class,
                () -> handler.handleRequest(mock(ScheduledEvent.class), mock(Context.class)));

        verify(cloudwatchMetricsService, never()).putEmbeddedValue(any(), anyDouble(), any());
    }
}
