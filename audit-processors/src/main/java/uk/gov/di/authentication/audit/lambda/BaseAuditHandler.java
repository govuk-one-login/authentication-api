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

import java.util.Base64;
import java.util.Optional;

public abstract class BaseAuditHandler implements RequestHandler<SNSEvent, Object> {

    private final Logger LOG = LoggerFactory.getLogger(getClass());

    @Override
    public Object handleRequest(SNSEvent input, Context context) {
        input.getRecords().stream()
                .map(SNSRecord::getSNS)
                .map(SNS::getMessage)
                .map(Base64.getDecoder()::decode)
                .map(this::parseToSignedAuditEvent)
                .map(this::validateSignatureAndExtract)
                .filter(Optional::isPresent)
                .map(Optional::get)
                .peek(event -> LOG.info("Consuming audit message with id: {}", event.getEventId()))
                .forEach(this::handleAuditEvent);

        return null;
    }

    abstract void handleAuditEvent(AuditEvent auditEvent);

    private Optional<AuditEvent> validateSignatureAndExtract(
            Optional<SignedAuditEvent> signedAuditEvent) {
        // TODO: Use signedAuditEvent.getSignature() to validate signedAuditEvent.getPayload()

        return signedAuditEvent
                .map(SignedAuditEvent::getPayload)
                .map(
                        payload -> {
                            try {
                                return AuditEvent.parseFrom(payload);
                            } catch (InvalidProtocolBufferException e) {
                                return null;
                            }
                        });
    }

    private Optional<SignedAuditEvent> parseToSignedAuditEvent(byte[] bytes) {
        try {
            return Optional.ofNullable(SignedAuditEvent.parseFrom(bytes));
        } catch (InvalidProtocolBufferException e) {
            return Optional.empty();
        }
    }
}
