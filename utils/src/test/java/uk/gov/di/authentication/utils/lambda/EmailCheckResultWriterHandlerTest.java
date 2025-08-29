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
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
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
    private static ArgumentCaptor<String> govukSigninJourneyIdCaptor;
    private static ArgumentCaptor<Object> emailCheckResponseCaptor;
    private EmailCheckResultWriterHandler handler;

    @BeforeAll
    static void init() {
        dbMock = mock(DynamoEmailCheckResultService.class);
        cloudWatchMock = mock(CloudwatchMetricsService.class);
        emailCaptor = ArgumentCaptor.forClass(String.class);
        statusCaptor = ArgumentCaptor.forClass(EmailCheckResultStatus.class);
        timeToExistCaptor = ArgumentCaptor.forClass(Long.class);
        referenceNumberCaptor = ArgumentCaptor.forClass(String.class);
        govukSigninJourneyIdCaptor = ArgumentCaptor.forClass(String.class);
        emailCheckResponseCaptor = ArgumentCaptor.forClass(Object.class);
    }

    @BeforeEach
    void setUp() {
        handler = new EmailCheckResultWriterHandler(dbMock, cloudWatchMock);
        Mockito.reset(dbMock, cloudWatchMock);
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
                            timeToExistCaptor.capture(), referenceNumberCaptor.capture(),
                            govukSigninJourneyIdCaptor.capture(),
                                    emailCheckResponseCaptor.capture());

            assertEquals(TEST_MSG_EMAIL, emailCaptor.getValue());
            assertEquals(emailCheckResultStatus, statusCaptor.getValue());
            assertEquals(TEST_MSG_TIME_TO_EXIST, timeToExistCaptor.getValue());
            assertEquals(TEST_MSG_REF_NUMBER, referenceNumberCaptor.getValue());
            assertEquals("test-journey-id", govukSigninJourneyIdCaptor.getValue());

            var capturedResponseSection = emailCheckResponseCaptor.getValue();
            assertNotNull(capturedResponseSection);

            var responseMap = (Map<?, ?>) capturedResponseSection;
            assertEquals("testValue1", responseMap.get("testString"));
            assertEquals(123, ((Number) responseMap.get("testNumber")).intValue());
            assertEquals(true, responseMap.get("testBoolean"));

            var testArray = (List<?>) responseMap.get("testArray");
            assertEquals(2, testArray.size());
            assertEquals("testItem1", testArray.get(0));
            assertEquals("testItem2", testArray.get(1));

            var testObject = (Map<?, ?>) responseMap.get("testObject");
            assertEquals("testNestedValue", testObject.get("testNestedString"));
            assertEquals(456, ((Number) testObject.get("testNestedNumber")).intValue());

            var testChildObject = (Map<?, ?>) testObject.get("testChildObject");
            assertEquals("testDeepValue", testChildObject.get("testDeepString"));
            assertEquals(false, testChildObject.get("testDeepBoolean"));

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

    @Test
    void shouldHandleV1Messages() {
        SQSEvent event = getSqsEventWithV1Message();

        handler.emailCheckResultWriterHandler(event);

        verify(dbMock)
                .saveEmailCheckResult(
                        emailCaptor.capture(),
                        statusCaptor.capture(),
                        timeToExistCaptor.capture(),
                        referenceNumberCaptor.capture(),
                        govukSigninJourneyIdCaptor.capture(),
                        emailCheckResponseCaptor.capture());

        assertEquals(TEST_MSG_EMAIL, emailCaptor.getValue());
        assertEquals(EmailCheckResultStatus.ALLOW, statusCaptor.getValue());
        assertEquals(TEST_MSG_TIME_TO_EXIST, timeToExistCaptor.getValue());
        assertEquals(TEST_MSG_REF_NUMBER, referenceNumberCaptor.getValue());
        assertNull(govukSigninJourneyIdCaptor.getValue());
        assertNull(emailCheckResponseCaptor.getValue());
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
                            """
                            {
                              "EmailAddress": "%s",
                              "Status": "%s",
                              "TimeToExist": "%d",
                              "RequestReference": "%s",
                              "TimeOfInitialRequest": %d,
                              "GovukSigninJourneyId": "test-journey-id",
                              "EmailCheckResponse": {
                                "testString": "testValue1",
                                "testNumber": 123,
                                "testBoolean": true,
                                "testArray": ["testItem1", "testItem2"],
                                "testObject": {
                                  "testNestedString": "testNestedValue",
                                  "testNestedNumber": 456,
                                  "testChildObject": {
                                    "testDeepString": "testDeepValue",
                                    "testDeepBoolean": false
                                  }
                                }
                              }
                            }""",
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

    @NotNull
    private static SQSEvent getSqsEventWithV1Message() {
        SQSEvent event = new SQSEvent();
        SQSMessage sqsMessage = new SQSMessage();

        sqsMessage.setBody(
                String.format(
                        "{ \"EmailAddress\": \"%s\", \"Status\": \"%s\", \"TimeToExist\": \"%d\", \"RequestReference\": \"%s\", \"TimeOfInitialRequest\":%d }",
                        TEST_MSG_EMAIL,
                        EmailCheckResultStatus.ALLOW.toString(),
                        TEST_MSG_TIME_TO_EXIST,
                        TEST_MSG_REF_NUMBER,
                        REQUEST_DURATION));

        List<SQSMessage> records = List.of(sqsMessage);
        event.setRecords(records);
        return event;
    }
}
