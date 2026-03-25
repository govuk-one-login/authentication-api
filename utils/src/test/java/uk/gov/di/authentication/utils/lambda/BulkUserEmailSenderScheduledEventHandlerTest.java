package uk.gov.di.authentication.utils.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.ScheduledEvent;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.EnumSource;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.DescribeTableResponse;
import software.amazon.awssdk.services.dynamodb.model.TableDescription;
import uk.gov.di.authentication.shared.entity.BulkEmailStatus;
import uk.gov.di.authentication.shared.entity.BulkEmailUserSendMode;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.BulkEmailUsersService;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.NotificationService;
import uk.gov.di.authentication.shared.services.mfa.MFAMethodsService;
import uk.gov.di.authentication.sharedtest.logging.CaptureLoggingExtension;
import uk.gov.di.authentication.utils.exceptions.IncludedTermsAndConditionsConfigMissingException;
import uk.gov.di.authentication.utils.exceptions.UnrecognisedSendModeException;
import uk.gov.di.authentication.utils.services.bulkemailsender.BulkEmailSender;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasItem;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.sharedtest.logging.LogEventMatcher.withMessageContaining;
import static uk.gov.di.authentication.utils.lambda.BulkUserEmailSenderScheduledEventHandler.DELIVERY_RECEIPT_STATUS_TEMPORARY_FAILURE;

class BulkUserEmailSenderScheduledEventHandlerTest {

    @RegisterExtension
    private final CaptureLoggingExtension logging =
            new CaptureLoggingExtension(BulkUserEmailSenderScheduledEventHandler.class);

    private BulkUserEmailSenderScheduledEventHandler bulkUserEmailSenderScheduledEventHandler;

    private final Context mockContext = mock(Context.class);
    private final BulkEmailUsersService bulkEmailUsersService = mock(BulkEmailUsersService.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final CloudwatchMetricsService cloudwatchMetricsService =
            mock(CloudwatchMetricsService.class);
    private final BulkEmailSender bulkEmailSender = mock(BulkEmailSender.class);
    private final NotificationService notificationService = mock(NotificationService.class);
    private final AuditService auditService = mock(AuditService.class);
    private final DynamoService dynamoService = mock(DynamoService.class);
    private final MFAMethodsService mfaMethodsService = mock(MFAMethodsService.class);
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
        when(configurationService.getBulkUserEmailBatchSize()).thenReturn(TEST_SUBJECT_IDS.length);
        when(configurationService.getBulkUserEmailTaskTimeoutSeconds()).thenReturn(15);
        when(configurationService.getBulkUserEmailStopNewRequestsAfterSeconds()).thenReturn(45);
        when(bulkEmailUsersService.getNSubjectIdsByStatus(anyInt(), any(), any()))
                .thenReturn(new BulkEmailUsersService.BulkEmailQueryResult(List.of(), Map.of()));
        when(bulkEmailUsersService.getNSubjectIdsByDeliveryReceiptStatus(anyInt(), any(), any()))
                .thenReturn(new BulkEmailUsersService.BulkEmailQueryResult(List.of(), Map.of()));
    }

    @ParameterizedTest
    @CsvSource({
        "TERMS_AND_CONDITIONS,TermsAndConditionsBulkEmailSender",
        "INTERNATIONAL_NUMBERS_FORCED_MFA_RESET,InternationalNumbersForcedMfaResetBulkEmailSender"
    })
    void shouldCreateCorrectSenderWhenConfigured(String senderType, String expectedClassName) {
        when(configurationService.getBulkUserEmailSenderType()).thenReturn(senderType);

        var handler =
                new BulkUserEmailSenderScheduledEventHandler(
                        configurationService,
                        bulkEmailUsersService,
                        cloudwatchMetricsService,
                        notificationService,
                        auditService,
                        dynamoService,
                        mfaMethodsService);

        assertEquals(expectedClassName, handler.getBulkEmailSenderClassName());
    }

    @Test
    void shouldThrowExceptionForUnknownSenderType() {
        when(configurationService.getBulkUserEmailSenderType()).thenReturn("UNKNOWN");

        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new BulkUserEmailSenderScheduledEventHandler(
                                configurationService,
                                bulkEmailUsersService,
                                cloudwatchMetricsService,
                                notificationService,
                                auditService,
                                dynamoService,
                                mfaMethodsService));
    }

    @ParameterizedTest
    @EnumSource(BulkEmailUserSendMode.class)
    void shouldCallBulkEmailSenderForEachSubjectIdInBatch(BulkEmailUserSendMode sendMode) {
        when(configurationService.getBulkEmailUserSendMode()).thenReturn(sendMode.getValue());

        var result =
                new BulkEmailUsersService.BulkEmailQueryResult(
                        Arrays.asList(TEST_SUBJECT_IDS), Map.of());

        switch (sendMode) {
            case PENDING:
                when(bulkEmailUsersService.getNSubjectIdsByStatus(
                                TEST_SUBJECT_IDS.length, BulkEmailStatus.PENDING, null))
                        .thenReturn(result);
                break;
            case NOTIFY_ERROR_RETRIES:
                when(bulkEmailUsersService.getNSubjectIdsByStatus(
                                TEST_SUBJECT_IDS.length, BulkEmailStatus.ERROR_SENDING_EMAIL, null))
                        .thenReturn(result);
                break;
            case DELIVERY_RECEIPT_TEMPORARY_FAILURE_RETRIES:
                when(bulkEmailUsersService.getNSubjectIdsByDeliveryReceiptStatus(
                                TEST_SUBJECT_IDS.length,
                                DELIVERY_RECEIPT_STATUS_TEMPORARY_FAILURE,
                                null))
                        .thenReturn(result);
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
    void shouldPublishTableSizeMetric() {
        bulkUserEmailSenderScheduledEventHandler.handleRequest(scheduledEvent, mockContext);

        verify(cloudwatchMetricsService, times(1))
                .putEmbeddedValue("NumberOfBulkEmailUsers", 1L, Map.of());
    }

    @Test
    void shouldReturnEarlyWhenBatchSizeIsZero() {
        when(configurationService.getBulkUserEmailBatchSize()).thenReturn(0);

        bulkUserEmailSenderScheduledEventHandler.handleRequest(scheduledEvent, mockContext);

        verify(bulkEmailSender, never()).validateConfiguration();
        verify(bulkEmailSender, never()).validateAndSendMessage(any(), any());
        verify(bulkEmailUsersService, never()).getNSubjectIdsByStatus(anyInt(), any(), any());
    }

    @Test
    void shouldProcessMultipleBatches() {
        when(configurationService.getBulkUserEmailBatchSize()).thenReturn(300);

        var key1 = Map.of("SubjectID", AttributeValue.fromS("id-1"));
        var key2 = Map.of("SubjectID", AttributeValue.fromS("id-2"));

        when(bulkEmailUsersService.getNSubjectIdsByStatus(100, BulkEmailStatus.PENDING, null))
                .thenReturn(new BulkEmailUsersService.BulkEmailQueryResult(List.of("id-1"), key1));
        when(bulkEmailUsersService.getNSubjectIdsByStatus(100, BulkEmailStatus.PENDING, key1))
                .thenReturn(new BulkEmailUsersService.BulkEmailQueryResult(List.of("id-2"), key2));
        when(bulkEmailUsersService.getNSubjectIdsByStatus(100, BulkEmailStatus.PENDING, key2))
                .thenReturn(
                        new BulkEmailUsersService.BulkEmailQueryResult(List.of("id-3"), Map.of()));

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
        when(configurationService.getBulkUserEmailBatchSize()).thenReturn(500);

        var key1 = Map.of("SubjectID", AttributeValue.fromS("id-1"));

        when(bulkEmailUsersService.getNSubjectIdsByStatus(100, BulkEmailStatus.PENDING, null))
                .thenReturn(new BulkEmailUsersService.BulkEmailQueryResult(List.of("id-1"), key1));
        when(bulkEmailUsersService.getNSubjectIdsByStatus(100, BulkEmailStatus.PENDING, key1))
                .thenReturn(new BulkEmailUsersService.BulkEmailQueryResult(List.of(), Map.of()));

        bulkUserEmailSenderScheduledEventHandler.handleRequest(scheduledEvent, mockContext);

        verify(bulkEmailSender, times(1))
                .validateAndSendMessage("id-1", BulkEmailUserSendMode.PENDING);
        verify(bulkEmailUsersService, times(2)).getNSubjectIdsByStatus(anyInt(), any(), any());
    }

    @Test
    void shouldNotLoopInfinitelyWhenFirstBatchIsEmpty() {
        when(configurationService.getBulkUserEmailBatchSize()).thenReturn(500);
        when(bulkEmailUsersService.getNSubjectIdsByStatus(100, BulkEmailStatus.PENDING, null))
                .thenReturn(new BulkEmailUsersService.BulkEmailQueryResult(List.of(), Map.of()));

        bulkUserEmailSenderScheduledEventHandler.handleRequest(scheduledEvent, mockContext);

        verify(bulkEmailSender, never()).validateAndSendMessage(any(), any());
        verify(bulkEmailUsersService, times(1)).getNSubjectIdsByStatus(anyInt(), any(), any());
    }

    @Test
    void shouldProcessRequestsInParallelUpTo10Concurrent() {
        AtomicInteger maxConcurrent = new AtomicInteger(0);
        AtomicInteger currentConcurrent = new AtomicInteger(0);
        CountDownLatch allStarted = new CountDownLatch(10);
        Set<String> processedIds = Collections.newSetFromMap(new ConcurrentHashMap<>());

        List<String> subjectIds =
                List.of(
                        "id-1", "id-2", "id-3", "id-4", "id-5", "id-6", "id-7", "id-8", "id-9",
                        "id-10", "id-11", "id-12");

        when(configurationService.getBulkUserEmailBatchSize()).thenReturn(subjectIds.size());
        when(bulkEmailUsersService.getNSubjectIdsByStatus(
                        subjectIds.size(), BulkEmailStatus.PENDING, null))
                .thenReturn(new BulkEmailUsersService.BulkEmailQueryResult(subjectIds, Map.of()));

        doAnswer(
                        invocation -> {
                            int concurrent = currentConcurrent.incrementAndGet();
                            maxConcurrent.updateAndGet(max -> Math.max(max, concurrent));
                            allStarted.countDown();
                            Thread.sleep(50);
                            processedIds.add(invocation.getArgument(0));
                            currentConcurrent.decrementAndGet();
                            return null;
                        })
                .when(bulkEmailSender)
                .validateAndSendMessage(any(), any());

        bulkUserEmailSenderScheduledEventHandler.handleRequest(scheduledEvent, mockContext);

        assertEquals(subjectIds.size(), processedIds.size());
        assertEquals(10, maxConcurrent.get());
    }

    @Test
    void shouldHandleTaskTimeoutWithoutThrowing() {
        when(configurationService.getBulkUserEmailBatchSize()).thenReturn(1);
        when(configurationService.getBulkUserEmailTaskTimeoutSeconds()).thenReturn(1);
        when(bulkEmailUsersService.getNSubjectIdsByStatus(1, BulkEmailStatus.PENDING, null))
                .thenReturn(
                        new BulkEmailUsersService.BulkEmailQueryResult(List.of("id-1"), Map.of()));

        doAnswer(
                        invocation -> {
                            Thread.sleep(2000); // Sleep longer than 1s timeout
                            return null;
                        })
                .when(bulkEmailSender)
                .validateAndSendMessage(any(), any());

        // Should complete without throwing, even though task times out
        bulkUserEmailSenderScheduledEventHandler.handleRequest(scheduledEvent, mockContext);

        verify(bulkEmailSender, times(1))
                .validateAndSendMessage("id-1", BulkEmailUserSendMode.PENDING);
    }

    @Test
    void shouldContinueProcessingOtherTasksWhenOneThrowsException() {
        when(configurationService.getBulkUserEmailBatchSize()).thenReturn(3);
        when(bulkEmailUsersService.getNSubjectIdsByStatus(3, BulkEmailStatus.PENDING, null))
                .thenReturn(
                        new BulkEmailUsersService.BulkEmailQueryResult(
                                List.of("id-1", "id-2", "id-3"), Map.of()));

        doThrow(new RuntimeException("Test exception"))
                .doNothing()
                .doNothing()
                .when(bulkEmailSender)
                .validateAndSendMessage(any(), any());

        bulkUserEmailSenderScheduledEventHandler.handleRequest(scheduledEvent, mockContext);

        verify(bulkEmailSender, times(3)).validateAndSendMessage(any(), any());
    }

    @Test
    void shouldNotExceedReasonableTotalTimeWhenMultipleTasksTimeout() {
        int numTasks = 3;
        int taskTimeoutSeconds = 1;

        when(configurationService.getBulkUserEmailBatchSize()).thenReturn(numTasks);
        when(configurationService.getBulkUserEmailTaskTimeoutSeconds())
                .thenReturn(taskTimeoutSeconds);
        when(bulkEmailUsersService.getNSubjectIdsByStatus(numTasks, BulkEmailStatus.PENDING, null))
                .thenReturn(
                        new BulkEmailUsersService.BulkEmailQueryResult(
                                List.of("id-1", "id-2", "id-3"), Map.of()));

        doAnswer(
                        invocation -> {
                            Thread.sleep(5000);
                            return null;
                        })
                .when(bulkEmailSender)
                .validateAndSendMessage(any(), any());

        long startTime = System.currentTimeMillis();
        bulkUserEmailSenderScheduledEventHandler.handleRequest(scheduledEvent, mockContext);
        long elapsedSeconds = (System.currentTimeMillis() - startTime) / 1000;

        assertEquals(
                true,
                elapsedSeconds < 2,
                "Expected completion in under 2s but took " + elapsedSeconds + "s");
    }

    @Test
    void shouldLogCorrectCountersForMixedOutcomes() {
        when(configurationService.getBulkUserEmailBatchSize()).thenReturn(12);
        when(configurationService.getBulkUserEmailTaskTimeoutSeconds()).thenReturn(2);
        when(configurationService.getBulkUserEmailStopNewRequestsAfterSeconds()).thenReturn(1);
        when(bulkEmailUsersService.getNSubjectIdsByStatus(12, BulkEmailStatus.PENDING, null))
                .thenReturn(
                        new BulkEmailUsersService.BulkEmailQueryResult(
                                List.of(
                                        "ok1",
                                        "ok2",
                                        "ok3",
                                        "ok4",
                                        "ok5",
                                        "ok6",
                                        "ok7",
                                        "ok8",
                                        "timeout",
                                        "exception",
                                        "skip"),
                                Map.of()));

        doAnswer(
                        invocation -> {
                            String subjectId = invocation.getArgument(0);
                            if ("timeout".equals(subjectId)) {
                                Thread.sleep(5000);
                            } else if ("exception".equals(subjectId)) {
                                Thread.sleep(1100);
                                throw new RuntimeException("Test exception");
                            } else if (subjectId.startsWith("ok")) {
                                Thread.sleep(1100);
                            }
                            return null;
                        })
                .when(bulkEmailSender)
                .validateAndSendMessage(any(), any());

        bulkUserEmailSenderScheduledEventHandler.handleRequest(scheduledEvent, mockContext);

        assertThat(logging.events(), hasItem(withMessageContaining("Total users: 11")));
        assertThat(logging.events(), hasItem(withMessageContaining("Processed: 8")));
        assertThat(logging.events(), hasItem(withMessageContaining("Skipped: 1")));
        assertThat(logging.events(), hasItem(withMessageContaining("Unhandled exceptions: 1")));
        assertThat(logging.events(), hasItem(withMessageContaining("Timed out: 1")));
    }

    @Test
    void shouldSkipTasksWhenTimeLimitExceeded() {
        AtomicInteger startedCount = new AtomicInteger(0);

        List<String> subjectIds =
                List.of(
                        "id-1", "id-2", "id-3", "id-4", "id-5", "id-6", "id-7", "id-8", "id-9",
                        "id-10", "id-11", "id-12", "id-13", "id-14", "id-15");

        when(configurationService.getBulkUserEmailBatchSize()).thenReturn(subjectIds.size());
        when(configurationService.getBulkUserEmailStopNewRequestsAfterSeconds()).thenReturn(1);
        when(configurationService.getBulkUserEmailTaskTimeoutSeconds()).thenReturn(5);
        when(bulkEmailUsersService.getNSubjectIdsByStatus(
                        subjectIds.size(), BulkEmailStatus.PENDING, null))
                .thenReturn(new BulkEmailUsersService.BulkEmailQueryResult(subjectIds, Map.of()));

        doAnswer(
                        invocation -> {
                            startedCount.incrementAndGet();
                            Thread.sleep(2000);
                            return null;
                        })
                .when(bulkEmailSender)
                .validateAndSendMessage(any(), any());

        bulkUserEmailSenderScheduledEventHandler.handleRequest(scheduledEvent, mockContext);

        assertEquals(10, startedCount.get());
    }
}
