package uk.gov.di.authentication.audit.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.SNSEvent;
import com.amazonaws.services.lambda.runtime.events.SNSEvent.SNS;
import com.amazonaws.services.lambda.runtime.events.SNSEvent.SNSRecord;
import com.google.protobuf.InvalidProtocolBufferException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.audit.AuditPayload.AuditEvent;
import uk.gov.di.audit.AuditPayload.SignedAuditEvent;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.KmsConnectionService;

import java.util.Base64;
import java.util.Optional;

public abstract class BaseAuditHandler implements RequestHandler<SNSEvent, Object> {

    private final Logger LOG = LoggerFactory.getLogger(getClass());
    private final KmsConnectionService kmsConnectionService;
    private final ConfigurationService service;

    BaseAuditHandler(KmsConnectionService kmsConnectionService, ConfigurationService service) {
        this.kmsConnectionService = kmsConnectionService;
        this.service = service;
    }

    @Override
    public Object handleRequest(SNSEvent input, Context context) {
        input.getRecords().stream()
                .map(SNSRecord::getSNS)
                .map(SNS::getMessage)
                .map(Base64.getDecoder()::decode)
                .map(this::parseToSignedAuditEvent)
                .filter(this::validateSignature)
                .map(this::extractPayload)
                .filter(Optional::isPresent)
                .map(Optional::get)
                .peek(event -> LOG.info("Consuming audit message with id: {}", event.getEventId()))
                .forEach(this::handleAuditEvent);

        return null;
    }

    abstract void handleAuditEvent(AuditEvent auditEvent);

    private Optional<AuditEvent> extractPayload(Optional<SignedAuditEvent> signedAuditEvent) {
        return signedAuditEvent
                .map(SignedAuditEvent::getPayload)
                .map(
                        payload -> {
                            try {
                                return AuditEvent.parseFrom(payload);
                            } catch (InvalidProtocolBufferException e) {
                                e.printStackTrace();
                                return null;
                            }
                        });
    }

    private boolean validateSignature(Optional<SignedAuditEvent> event) {
        if (event.isEmpty()) {
            return false;
        }

        return kmsConnectionService.validateSignature(
                event.get().getSignature().asReadOnlyByteBuffer(),
                event.get().getPayload().asReadOnlyByteBuffer(),
                service.getAuditSigningKeyAlias());
    }

    private Optional<SignedAuditEvent> parseToSignedAuditEvent(byte[] bytes) {
        try {
            return Optional.ofNullable(SignedAuditEvent.parseFrom(bytes));
        } catch (InvalidProtocolBufferException e) {
            e.printStackTrace();
            return Optional.empty();
        }
    }
}
