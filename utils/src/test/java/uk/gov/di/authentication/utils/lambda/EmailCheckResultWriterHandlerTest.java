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
import uk.gov.di.authentication.shared.entity.EmailCheckResponse;
import uk.gov.di.authentication.shared.entity.EmailCheckResultStatus;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.DynamoEmailCheckResultService;

import java.time.Instant;
import java.util.Date;
import java.util.List;

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
    private static ArgumentCaptor<EmailCheckResponse> emailCheckResponseCaptor;
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
        emailCheckResponseCaptor = ArgumentCaptor.forClass(EmailCheckResponse.class);
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

            var capturedEmailCheckResponse = emailCheckResponseCaptor.getValue();
            assertNotNull(capturedEmailCheckResponse);

            var extensions = capturedEmailCheckResponse.extensions().getAsJsonObject();
            assertEquals("testValue1", extensions.get("extensionsTestString").getAsString());
            assertEquals(123, extensions.get("extensionsTestNumber").getAsNumber().intValue());
            assertEquals(true, extensions.get("extensionsTestBoolean").getAsBoolean());

            var testObject = extensions.get("extensionsTestObject").getAsJsonObject();
            assertEquals(
                    "testNestedValue", testObject.get("extensionsTestNestedString").getAsString());
            assertEquals(
                    456, testObject.get("extensionsTestNestedNumber").getAsNumber().intValue());

            var testChildObject = testObject.get("extensionsTestChildObject").getAsJsonObject();
            assertEquals(
                    "testDeepValue", testChildObject.get("extensionsTestDeepString").getAsString());
            assertEquals(false, testChildObject.get("extensionsTestDeepBoolean").getAsBoolean());

            var restricted = capturedEmailCheckResponse.restricted().getAsJsonObject();
            assertEquals("testValue2", restricted.get("restrictedTestString").getAsString());

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
                                "extensions": {
                                    "extensionsTestString": "testValue1",
                                    "extensionsTestNumber": 123,
                                    "extensionsTestBoolean": true,
                                    "extensionsTestArray": ["testItem1", "testItem2"],
                                    "extensionsTestObject": {
                                      "extensionsTestNestedString": "testNestedValue",
                                      "extensionsTestNestedNumber": 456,
                                      "extensionsTestChildObject": {
                                        "extensionsTestDeepString": "testDeepValue",
                                        "extensionsTestDeepBoolean": false
                                      }
                                    }
                                },
                                "restricted": {
                                    "restrictedTestString": "testValue2"
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
