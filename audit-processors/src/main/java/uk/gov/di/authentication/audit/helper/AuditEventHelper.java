package uk.gov.di.authentication.audit.helper;

import com.google.protobuf.InvalidProtocolBufferException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.audit.AuditPayload.AuditEvent;
import uk.gov.di.audit.AuditPayload.SignedAuditEvent;

import java.util.Optional;

public class AuditEventHelper {

    private static final Logger LOG = LogManager.getLogger(AuditEventHelper.class);

    public static Optional<AuditEvent> extractPayload(Optional<SignedAuditEvent> signedAuditEvent) {
        return signedAuditEvent
                .map(SignedAuditEvent::getPayload)
                .map(
                        payload -> {
                            try {
                                return AuditEvent.parseFrom(payload);
                            } catch (InvalidProtocolBufferException e) {
                                LOG.error("Could not parse AuditEvent payload");
                                return null;
                            }
                        });
    }

    public static Optional<SignedAuditEvent> parseToSignedAuditEvent(byte[] bytes) {
        try {
            return Optional.ofNullable(SignedAuditEvent.parseFrom(bytes));
        } catch (InvalidProtocolBufferException e) {
            LOG.error("Could not parse SignedAuditEvent payload");
            return Optional.empty();
        }
    }
}
