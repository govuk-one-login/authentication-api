package uk.gov.di.authentication.oidc.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.SQSBatchResponse;
import com.amazonaws.services.lambda.runtime.events.SQSEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;
import uk.gov.di.orchestration.shared.entity.GlobalLogoutMessage;
import uk.gov.di.orchestration.shared.serialization.Json;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.GlobalLogoutService;
import uk.gov.di.orchestration.shared.services.SerializationService;

import java.util.ArrayList;
import java.util.List;

import static uk.gov.di.authentication.oidc.validators.GlobalLogoutValidator.validate;
import static uk.gov.di.orchestration.shared.helpers.InstrumentationHelper.segmentedFunctionCall;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.AWS_REQUEST_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.attachLogFieldToLogs;

public class GlobalLogoutHandler implements RequestHandler<SQSEvent, Object> {
    private static final Logger LOG = LogManager.getLogger(GlobalLogoutHandler.class);
    private final GlobalLogoutService globalLogoutService;

    public GlobalLogoutHandler() {
        this(ConfigurationService.getInstance());
    }

    public GlobalLogoutHandler(ConfigurationService configurationService) {
        this(new GlobalLogoutService(configurationService));
    }

    public GlobalLogoutHandler(GlobalLogoutService globalLogoutService) {
        this.globalLogoutService = globalLogoutService;
    }

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
            } catch (Json.JsonException e) {
                LOG.error("Could not parse logout request payload", e);
                batchItemFailures.add(
                        new SQSBatchResponse.BatchItemFailure(message.getMessageId()));
            } catch (RuntimeException e) {
                LOG.warn(e.getMessage());
                batchItemFailures.add(
                        new SQSBatchResponse.BatchItemFailure(message.getMessageId()));
            }
        }
        return new SQSBatchResponse(batchItemFailures);
    }

    private void processMessage(SQSEvent.SQSMessage message) throws Json.JsonException {
        var request =
                SerializationService.getInstance()
                        .readValue(message.getBody(), GlobalLogoutMessage.class);
        validate(request);
        LOG.info(
                "Received request with event id {} to global logout user with session {} and client session {}",
                request.eventId(),
                request.sessionId(),
                request.clientSessionId());
        globalLogoutService.logoutAllSessions(request);
    }
}
