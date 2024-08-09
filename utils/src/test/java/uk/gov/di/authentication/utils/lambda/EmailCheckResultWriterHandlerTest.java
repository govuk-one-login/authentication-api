package uk.gov.di.authentication.utils.lambda;

import com.amazonaws.services.lambda.runtime.events.SQSEvent;
import com.amazonaws.services.lambda.runtime.events.SQSEvent.SQSMessage;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import software.amazon.awssdk.annotations.NotNull;
import uk.gov.di.authentication.shared.entity.EmailCheckResultStatus;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.DynamoEmailCheckResultService;

import java.time.Instant;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class EmailCheckResultWriterHandlerTest {
    private static final String TEST_MSG_EMAIL = "test@test.com";
    private static final long TEST_MSG_TIME_TO_EXIST = 1706870420L;
    private static final String TEST_MSG_REF_NUMBER = "123456-abc1234def5678";
    private static final long TEST_TIME_OF_INITIAL_REQUEST = Instant.now().toEpochMilli();
    private static final long REQUEST_DURATION = 1000L;
    private static final long TEST_TIME_NOW = TEST_TIME_OF_INITIAL_REQUEST + REQUEST_DURATION;
    private static DynamoEmailCheckResultService dbMock;
    private static CloudwatchMetricsService cloudWatchMock;
    private static ArgumentCaptor<String> emailCaptor;
    private static ArgumentCaptor<EmailCheckResultStatus> statusCaptor;
    private static ArgumentCaptor<Long> timeToExistCaptor;
    private static ArgumentCaptor<String> referenceNumberCaptor;
    private EmailCheckResultWriterHandler handler;

    @BeforeAll
    static void init() {
        dbMock = mock(DynamoEmailCheckResultService.class);
        cloudWatchMock = mock(CloudwatchMetricsService.class);
        emailCaptor = ArgumentCaptor.forClass(String.class);
        statusCaptor = ArgumentCaptor.forClass(EmailCheckResultStatus.class);
        timeToExistCaptor = ArgumentCaptor.forClass(Long.class);
        referenceNumberCaptor = ArgumentCaptor.forClass(String.class);
    }

    @BeforeEach
    void setUp() {
        handler = new EmailCheckResultWriterHandler(dbMock, cloudWatchMock);
    }

    @Test
    void shouldProcessValidSQSEventWithSingleMessageAndSaveToDatabase() {
        var emailCheckResultStatus = EmailCheckResultStatus.ALLOW;
        SQSEvent event = getSqsEventWithSingleMessage(true, emailCheckResultStatus);
        try (MockedStatic<NowHelper> mockedNowHelperClass = Mockito.mockStatic(NowHelper.class)) {
            mockedNowHelperClass
                    .when(NowHelper::now)
                    .thenReturn(Date.from(Instant.ofEpochMilli(TEST_TIME_NOW)));
            handler.emailCheckResultWriterHandler(event);

            verify(dbMock)
                    .saveEmailCheckResult(
                            emailCaptor.capture(), statusCaptor.capture(),
                            timeToExistCaptor.capture(), referenceNumberCaptor.capture());

            assertEquals(TEST_MSG_EMAIL, emailCaptor.getValue());
            assertEquals(emailCheckResultStatus, statusCaptor.getValue());
            assertEquals(TEST_MSG_TIME_TO_EXIST, timeToExistCaptor.getValue());
            assertEquals(TEST_MSG_REF_NUMBER, referenceNumberCaptor.getValue());
            verify(cloudWatchMock).logEmailCheckDuration(REQUEST_DURATION);
        }
    }

    @Test
    void shouldRethrowRuntimeErrorOnSQSEventWithSingleInvalidMessage() {
        SQSEvent event = getSqsEventWithSingleMessage(false);

        RuntimeException thrown =
                assertThrows(
                        RuntimeException.class, () -> handler.emailCheckResultWriterHandler(event));

        assertEquals(
                "Error when mapping message from queue to a EmailCheckResultSqsMessage",
                thrown.getMessage());
    }

    @NotNull
    private static SQSEvent getSqsEventWithSingleMessage(boolean doesMessageContainRequiredFields) {
        return getSqsEventWithSingleMessage(
                doesMessageContainRequiredFields, EmailCheckResultStatus.ALLOW);
    }

    @NotNull
    private static SQSEvent getSqsEventWithSingleMessage(
            boolean doesMessageContainRequiredFields, EmailCheckResultStatus status) {
        SQSEvent event = new SQSEvent();
        SQSMessage sqsMessage = new SQSMessage();

        if (doesMessageContainRequiredFields) {
            sqsMessage.setBody(
                    String.format(
                            "{ \"EmailAddress\": \"%s\", \"Status\": \"%s\", \"TimeToExist\": \"%d\", \"RequestReference\": \"%s\", \"TimeOfInitialRequest\":%d }",
                            TEST_MSG_EMAIL,
                            status.toString(),
                            TEST_MSG_TIME_TO_EXIST,
                            TEST_MSG_REF_NUMBER,
                            TEST_TIME_OF_INITIAL_REQUEST));
        } else {
            sqsMessage.setBody(("{}"));
        }

        List<SQSMessage> records = List.of(sqsMessage);
        event.setRecords(records);
        return event;
    }
}
