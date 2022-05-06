package uk.gov.di.authentication.audit.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.SNSEvent;
import com.amazonaws.services.lambda.runtime.events.SNSEvent.SNS;
import com.amazonaws.services.lambda.runtime.events.SNSEvent.SNSRecord;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.audit.AuditPayload.AuditEvent;
import uk.gov.di.audit.AuditPayload.SignedAuditEvent;
import uk.gov.di.audit.helper.AuditEventHelper;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.KmsConnectionService;

import java.util.Base64;
import java.util.Optional;

import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.segmentedFunctionCall;

public abstract class BaseAuditHandler implements RequestHandler<SNSEvent, Object> {

    protected final Logger LOG = LogManager.getLogger(getClass());
    private final KmsConnectionService kmsConnectionService;
    protected final ConfigurationService service;

    BaseAuditHandler(KmsConnectionService kmsConnectionService, ConfigurationService service) {
        this.kmsConnectionService = kmsConnectionService;
        this.service = service;
    }

    BaseAuditHandler() {
        this.service = ConfigurationService.getInstance();
        this.kmsConnectionService = new KmsConnectionService(service);
    }

    @Override
    public Object handleRequest(SNSEvent input, Context context) {
        segmentedFunctionCall("audit-processors::" + getClass().getSimpleName(), () -> {
            input.getRecords().stream()
                    .map(SNSRecord::getSNS)
                    .map(SNS::getMessage)
                    .map(Base64.getDecoder()::decode)
                    .map(AuditEventHelper::parseToSignedAuditEvent)
                    .filter(this::validateSignature)
                    .map(AuditEventHelper::extractPayload)
                    .filter(Optional::isPresent)
                    .map(Optional::get)
                    .peek(event -> LOG.info("Consuming audit message with id: {}", event.getEventId()))
                    .forEach(this::handleAuditEvent);
        });

        return null;
    }

    abstract void handleAuditEvent(AuditEvent auditEvent);

    private boolean validateSignature(Optional<SignedAuditEvent> event) {
        if (event.isEmpty()) {
            return false;
        }

        return kmsConnectionService.validateSignature(
                event.get().getSignature().asReadOnlyByteBuffer(),
                event.get().getPayload().asReadOnlyByteBuffer(),
                service.getAuditSigningKeyAlias());
    }
}
