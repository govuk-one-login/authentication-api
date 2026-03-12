package uk.gov.di.authentication.utils.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.ScheduledEvent;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import software.amazon.awssdk.services.dynamodb.model.DescribeTableResponse;
import software.amazon.awssdk.services.dynamodb.model.TableDescription;
import uk.gov.di.authentication.shared.entity.BulkEmailStatus;
import uk.gov.di.authentication.shared.entity.BulkEmailUserSendMode;
import uk.gov.di.authentication.shared.services.BulkEmailUsersService;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.utils.exceptions.IncludedTermsAndConditionsConfigMissingException;
import uk.gov.di.authentication.utils.exceptions.UnrecognisedSendModeException;
import uk.gov.di.authentication.utils.services.bulkemailsender.BulkEmailSender;

import java.util.*;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.utils.lambda.BulkUserEmailSenderScheduledEventHandler.DELIVERY_RECEIPT_STATUS_TEMPORARY_FAILURE;

class BulkUserEmailSenderScheduledEventHandlerTest {

    private BulkUserEmailSenderScheduledEventHandler bulkUserEmailSenderScheduledEventHandler;

    private final Context mockContext = mock(Context.class);
    private final BulkEmailUsersService bulkEmailUsersService = mock(BulkEmailUsersService.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final CloudwatchMetricsService cloudwatchMetricsService =
            mock(CloudwatchMetricsService.class);
    private final BulkEmailSender bulkEmailSender = mock(BulkEmailSender.class);
    private final DescribeTableResponse describeTableResponse = mock(DescribeTableResponse.class);
    private final ScheduledEvent scheduledEvent = mock(ScheduledEvent.class);

    private static final String[] TEST_SUBJECT_IDS = {
        "subject-id-1", "subject-id-2", "subject-id-3", "subject-id-4", "subject-id-5",
    };

    @BeforeEach
    void setUp() {
        bulkUserEmailSenderScheduledEventHandler =
                new BulkUserEmailSenderScheduledEventHandler(
                        bulkEmailUsersService,
                        configurationService,
                        cloudwatchMetricsService,
                        bulkEmailSender);
        when(bulkEmailUsersService.describeTable()).thenReturn(describeTableResponse);
        when(describeTableResponse.table())
                .thenReturn(TableDescription.builder().itemCount(1L).build());
        when(configurationService.getEnvironment()).thenReturn("unit-test");
        when(configurationService.getBulkEmailUserSendMode()).thenReturn("PENDING");
        when(configurationService.getBulkUserEmailBatchQueryLimit())
                .thenReturn(TEST_SUBJECT_IDS.length);
        when(configurationService.getBulkUserEmailMaxBatchCount()).thenReturn(1);
        when(configurationService.getBulkUserEmailBatchPauseDuration()).thenReturn(1L);
        when(bulkEmailUsersService.getNSubjectIdsByStatus(anyInt(), any())).thenReturn(List.of());
        when(bulkEmailUsersService.getNSubjectIdsByDeliveryReceiptStatus(anyInt(), any()))
                .thenReturn(List.of());
    }

    @ParameterizedTest
    @EnumSource(BulkEmailUserSendMode.class)
    void shouldCallBulkEmailSenderForEachSubjectIdInBatch(BulkEmailUserSendMode sendMode) {
        when(configurationService.getBulkEmailUserSendMode()).thenReturn(sendMode.getValue());

        switch (sendMode) {
            case PENDING:
                when(bulkEmailUsersService.getNSubjectIdsByStatus(
                                TEST_SUBJECT_IDS.length, BulkEmailStatus.PENDING))
                        .thenReturn(Arrays.asList(TEST_SUBJECT_IDS));
                break;
            case NOTIFY_ERROR_RETRIES:
                when(bulkEmailUsersService.getNSubjectIdsByStatus(
                                TEST_SUBJECT_IDS.length, BulkEmailStatus.ERROR_SENDING_EMAIL))
                        .thenReturn(Arrays.asList(TEST_SUBJECT_IDS));
                break;
            case DELIVERY_RECEIPT_TEMPORARY_FAILURE_RETRIES:
                when(bulkEmailUsersService.getNSubjectIdsByDeliveryReceiptStatus(
                                TEST_SUBJECT_IDS.length, DELIVERY_RECEIPT_STATUS_TEMPORARY_FAILURE))
                        .thenReturn(Arrays.asList(TEST_SUBJECT_IDS));
                break;
        }

        bulkUserEmailSenderScheduledEventHandler.handleRequest(scheduledEvent, mockContext);

        for (String subjectId : TEST_SUBJECT_IDS) {
            verify(bulkEmailSender, times(1)).validateAndSendMessage(subjectId, sendMode);
        }
    }

    @Test
    void shouldThrowUnrecognisedSendModeException() {
        when(configurationService.getBulkEmailUserSendMode()).thenReturn("INVALID_SEND_MODE");

        assertThrows(
                UnrecognisedSendModeException.class,
                () ->
                        bulkUserEmailSenderScheduledEventHandler.handleRequest(
                                scheduledEvent, mockContext));
        verify(bulkEmailSender, never()).validateAndSendMessage(any(), any());
    }

    @Test
    void shouldThrowIncludedTermsAndConditionsConfigMissingException() {
        doThrow(new IncludedTermsAndConditionsConfigMissingException())
                .when(bulkEmailSender)
                .validateConfiguration();

        assertThrows(
                IncludedTermsAndConditionsConfigMissingException.class,
                () ->
                        bulkUserEmailSenderScheduledEventHandler.handleRequest(
                                scheduledEvent, mockContext));
        verify(bulkEmailSender, never()).validateAndSendMessage(any(), any());
    }

    @Test
    void shouldProcessMultipleBatches() {
        when(configurationService.getBulkUserEmailMaxBatchCount()).thenReturn(3);
        when(bulkEmailUsersService.getNSubjectIdsByStatus(
                        TEST_SUBJECT_IDS.length, BulkEmailStatus.PENDING))
                .thenReturn(List.of("id-1"))
                .thenReturn(List.of("id-2"))
                .thenReturn(List.of("id-3"));

        bulkUserEmailSenderScheduledEventHandler.handleRequest(scheduledEvent, mockContext);

        verify(bulkEmailSender, times(1))
                .validateAndSendMessage("id-1", BulkEmailUserSendMode.PENDING);
        verify(bulkEmailSender, times(1))
                .validateAndSendMessage("id-2", BulkEmailUserSendMode.PENDING);
        verify(bulkEmailSender, times(1))
                .validateAndSendMessage("id-3", BulkEmailUserSendMode.PENDING);
    }

    @Test
    void shouldStopProcessingWhenBatchIsEmpty() {
        when(configurationService.getBulkUserEmailMaxBatchCount()).thenReturn(10);
        when(bulkEmailUsersService.getNSubjectIdsByStatus(
                        TEST_SUBJECT_IDS.length, BulkEmailStatus.PENDING))
                .thenReturn(List.of("id-1"))
                .thenReturn(List.of());

        bulkUserEmailSenderScheduledEventHandler.handleRequest(scheduledEvent, mockContext);

        verify(bulkEmailSender, times(1))
                .validateAndSendMessage("id-1", BulkEmailUserSendMode.PENDING);
        verify(bulkEmailUsersService, times(2)).getNSubjectIdsByStatus(anyInt(), any());
    }

    @Test
    void shouldPublishTableSizeMetric() {
        bulkUserEmailSenderScheduledEventHandler.handleRequest(scheduledEvent, mockContext);

        verify(cloudwatchMetricsService, times(1))
                .putEmbeddedValue("NumberOfBulkEmailUsers", 1L, Map.of());
    }
}
