package uk.gov.di.authentication.utils.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.SQSEvent;
import com.amazonaws.services.lambda.runtime.events.SQSEvent.SQSMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.shared.entity.EmailCheckResultSqsMessage;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.serialization.Json.JsonException;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoEmailCheckResultService;
import uk.gov.di.authentication.shared.services.SerializationService;

import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.segmentedFunctionCall;

public class EmailCheckResultWriterHandler implements RequestHandler<SQSEvent, Void> {

    private static final Logger LOG = LogManager.getLogger(EmailCheckResultWriterHandler.class);
    private final Json objectMapper = SerializationService.getInstance();
    private final DynamoEmailCheckResultService db;

    public EmailCheckResultWriterHandler(DynamoEmailCheckResultService databaseService) {
        this.db = databaseService;
    }

    public EmailCheckResultWriterHandler(ConfigurationService configService) {
        this.db = new DynamoEmailCheckResultService(configService);
    }

    public EmailCheckResultWriterHandler() {
        this(ConfigurationService.getInstance());
    }

    @Override
    public Void handleRequest(SQSEvent event, Context context) {
        return segmentedFunctionCall(
                "shared-api::" + getClass().getSimpleName(),
                () -> emailCheckResultWriterHandler(event));
    }

    public Void emailCheckResultWriterHandler(SQSEvent event) {
        LOG.info(
                "EmailCheckResultWriterHandler has been invoked with {} record(s)",
                event.getRecords().size());
        for (SQSMessage msg : event.getRecords()) {
            try {
                LOG.info("Message received from SQS queue");
                EmailCheckResultSqsMessage emailCheckResult =
                        objectMapper.readValue(msg.getBody(), EmailCheckResultSqsMessage.class);

                db.saveEmailCheckResult(
                        emailCheckResult.email(),
                        emailCheckResult.emailCheckResultStatus(),
                        emailCheckResult.timeToExist(),
                        emailCheckResult.referenceNumber());

                LOG.info(
                        "Message for email check reference {} written to database",
                        emailCheckResult.referenceNumber());

            } catch (JsonException e) {
                LOG.error("Error when mapping message from queue to a EmailCheckResultSqsMessage");
                throw new RuntimeException(
                        "Error when mapping message from queue to a EmailCheckResultSqsMessage", e);
            } catch (Exception e) {
                LOG.error("An unexpected error occurred in the EmailCheckResultWriterHandler", e);
                throw new RuntimeException(
                        "An unexpected error occurred in the EmailCheckResultWriterHandler", e);
            }
        }
        return null;
    }
}
