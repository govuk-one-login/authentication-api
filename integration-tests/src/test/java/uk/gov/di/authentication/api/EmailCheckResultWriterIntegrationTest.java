package uk.gov.di.authentication.api;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.SQSEvent;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import software.amazon.awssdk.annotations.NotNull;
import uk.gov.di.authentication.shared.entity.EmailCheckResultStatus;
import uk.gov.di.authentication.shared.entity.EmailCheckResultStore;
import uk.gov.di.authentication.shared.services.DynamoEmailCheckResultService;
import uk.gov.di.authentication.sharedtest.basetest.HandlerIntegrationTest;
import uk.gov.di.authentication.sharedtest.extensions.EmailCheckResultExtension;
import uk.gov.di.authentication.utils.lambda.EmailCheckResultWriterHandler;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;

class EmailCheckResultWriterIntegrationTest extends HandlerIntegrationTest<SQSEvent, Void> {
    private static final String TEST_MSG_EMAIL = "test@test.com";
    private static final long TEST_MSG_TIME_TO_EXIST = 4073717403L;
    private static final String TEST_MSG_REF_NUMBER = "123456-abc1234def5678";
    DynamoEmailCheckResultService dynamoEmailCheckResultService =
            new DynamoEmailCheckResultService(TEST_CONFIGURATION_SERVICE);

    @RegisterExtension
    protected static final EmailCheckResultExtension emailCheckResultExtension =
            new EmailCheckResultExtension();

    @BeforeEach
    void setup() {
        handler = new EmailCheckResultWriterHandler(TEST_CONFIGURATION_SERVICE);
    }

    @Test
    void shouldSaveSqsContentToEmailCheckResultStoreWhenReceivingAValidSqsEvent() {
        var emailCheckResultStatus = EmailCheckResultStatus.ALLOW;
        SQSEvent event = getSqsEventWithSingleMessage(true, emailCheckResultStatus);

        handler.handleRequest(event, mock(Context.class));

        EmailCheckResultStore dbEntry =
                dynamoEmailCheckResultService.getEmailCheckStore(TEST_MSG_EMAIL).get();
        assertEquals(TEST_MSG_EMAIL, dbEntry.getEmail());
        assertEquals(emailCheckResultStatus, dbEntry.getStatus());
        assertEquals(TEST_MSG_REF_NUMBER, dbEntry.getReferenceNumber());
        assertEquals(TEST_MSG_TIME_TO_EXIST, dbEntry.getTimeToExist());
    }

    @NotNull
    private static SQSEvent getSqsEventWithSingleMessage(
            boolean doesMessageContainRequiredFields, EmailCheckResultStatus status) {
        SQSEvent event = new SQSEvent();
        SQSEvent.SQSMessage sqsMessage = new SQSEvent.SQSMessage();

        if (doesMessageContainRequiredFields) {
            sqsMessage.setBody(
                    String.format(
                            "{ \"EmailAddress\": \"%s\", \"Status\": \"%s\", \"TimeToExist\": \"%d\", \"RequestReference\": \"%s\", \"TimeOfInitialRequest\":1000 }",
                            TEST_MSG_EMAIL,
                            status.toString(),
                            TEST_MSG_TIME_TO_EXIST,
                            TEST_MSG_REF_NUMBER));
        } else {
            sqsMessage.setBody(("{}"));
        }

        List<SQSEvent.SQSMessage> records = List.of(sqsMessage);
        event.setRecords(records);
        return event;
    }
}
