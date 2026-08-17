package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.SQSBatchResponse;
import com.amazonaws.services.lambda.runtime.events.SQSEvent;
import com.amazonaws.services.lambda.runtime.events.SQSEvent.SQSMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.accountmanagement.entity.InactiveAccountDeletionMessage;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.serialization.Json.JsonException;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SerializationService;

import java.util.ArrayList;

import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.segmentedFunctionCall;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachTraceId;

public class InactiveAccountDeletionHandler implements RequestHandler<SQSEvent, SQSBatchResponse> {

    private static final Logger LOG = LogManager.getLogger(InactiveAccountDeletionHandler.class);

    private final Json objectMapper = SerializationService.getInstance();
    private final ConfigurationService configurationService;

    public InactiveAccountDeletionHandler() {
        this(ConfigurationService.getInstance());
    }

    public InactiveAccountDeletionHandler(ConfigurationService configurationService) {
        this.configurationService = configurationService;
    }

    @Override
    public SQSBatchResponse handleRequest(SQSEvent event, Context context) {
        return segmentedFunctionCall(
                "account-management-api::" + getClass().getSimpleName(),
                () -> processMessages(event));
    }

    public SQSBatchResponse processMessages(SQSEvent event) {
        attachTraceId();

        var failures = new ArrayList<SQSBatchResponse.BatchItemFailure>();

        if (event == null || event.getRecords() == null) {
            LOG.warn("Received null event or null records");
            return new SQSBatchResponse(failures);
        }

        LOG.info("Processing inactive account deletion batch, size: {}", event.getRecords().size());

        for (SQSMessage msg : event.getRecords()) {
            try {
                var message = parseMessage(msg);
                LOG.info(
                        "Processing inactive account deletion for publicSubjectId: {}",
                        message.publicSubjectId());
                throw new UnsupportedOperationException("Deletion not yet implemented");
            } catch (Exception e) {
                LOG.error(
                        "Failed to process inactive account deletion message with id: {}",
                        msg.getMessageId(),
                        e);
                failures.add(new SQSBatchResponse.BatchItemFailure(msg.getMessageId()));
            }
        }

        LOG.info(
                "Completed batch processing. Failures: {}/{}",
                failures.size(),
                event.getRecords().size());
        return new SQSBatchResponse(failures);
    }

    private InactiveAccountDeletionMessage parseMessage(SQSMessage msg) throws JsonException {
        var message = objectMapper.readValue(msg.getBody(), InactiveAccountDeletionMessage.class);
        if (message.publicSubjectId() == null || message.publicSubjectId().isBlank()) {
            throw new IllegalArgumentException(
                    "publicSubjectId is missing or blank in message: " + msg.getMessageId());
        }
        return message;
    }
}
