package uk.gov.di.authentication.oidc.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.SQSBatchResponse;
import com.amazonaws.services.lambda.runtime.events.SQSEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;

import java.util.ArrayList;
import java.util.List;

import static uk.gov.di.orchestration.shared.helpers.InstrumentationHelper.segmentedFunctionCall;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.AWS_REQUEST_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.attachLogFieldToLogs;

public class GlobalLogoutHandler implements RequestHandler<SQSEvent, Object> {
    private static final Logger LOG = LogManager.getLogger(GlobalLogoutHandler.class);

    public GlobalLogoutHandler() {}

    @Override
    public Object handleRequest(SQSEvent sqsEvent, Context context) {
        ThreadContext.clearMap();
        attachLogFieldToLogs(AWS_REQUEST_ID, context.getAwsRequestId());
        return segmentedFunctionCall(
                "oidc-api::" + getClass().getSimpleName(), () -> processEvents(sqsEvent));
    }

    private Object processEvents(SQSEvent sqsEvent) {
        List<SQSBatchResponse.BatchItemFailure> batchItemFailures = new ArrayList<>();
        for (SQSEvent.SQSMessage message : sqsEvent.getRecords()) {
            LOG.info("Handling global logout request with id: {}", message.getMessageId());
            try {
                processMessage(message);
            } catch (RuntimeException e) {
                LOG.warn(e.getMessage());
                batchItemFailures.add(
                        new SQSBatchResponse.BatchItemFailure(message.getMessageId()));
            }
        }
        return new SQSBatchResponse(batchItemFailures);
    }

    private void processMessage(SQSEvent.SQSMessage message) {
        // TODO: Add validation for message (ATO-1658)
        //       Add logic for global logout (ATO-1660)
    }
}
