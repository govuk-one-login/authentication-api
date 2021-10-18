package uk.gov.di.authentication.audit.helper;

import com.google.protobuf.InvalidProtocolBufferException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.audit.AuditPayload.AuditEvent;
import uk.gov.di.audit.AuditPayload.SignedAuditEvent;

import java.util.Optional;

public class AuditEventHelper {

    private static final Logger LOG = LoggerFactory.getLogger(AuditEventHelper.class);

    public static Optional<AuditEvent> extractPayload(Optional<SignedAuditEvent> signedAuditEvent) {
        return signedAuditEvent
                .map(SignedAuditEvent::getPayload)
                .map(
                        payload -> {
                            try {
                                return AuditEvent.parseFrom(payload);
                            } catch (InvalidProtocolBufferException e) {
                                LOG.error("Could not parse AuditEvent payload", e);
                                return null;
                            }
                        });
    }

    public static Optional<SignedAuditEvent> parseToSignedAuditEvent(byte[] bytes) {
        try {
            return Optional.ofNullable(SignedAuditEvent.parseFrom(bytes));
        } catch (InvalidProtocolBufferException e) {
            LOG.error("Could not parse SignedAuditEvent payload", e);
            return Optional.empty();
        }
    }
}
