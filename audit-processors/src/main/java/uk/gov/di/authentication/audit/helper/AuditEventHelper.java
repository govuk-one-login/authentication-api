package uk.gov.di.authentication.audit.helper;

import com.google.protobuf.InvalidProtocolBufferException;
import uk.gov.di.audit.AuditPayload.AuditEvent;
import uk.gov.di.audit.AuditPayload.SignedAuditEvent;

import java.util.Optional;

public class AuditEventHelper {

    public static Optional<AuditEvent> extractPayload(Optional<SignedAuditEvent> signedAuditEvent) {
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

    public static Optional<SignedAuditEvent> parseToSignedAuditEvent(byte[] bytes) {
        try {
            return Optional.ofNullable(SignedAuditEvent.parseFrom(bytes));
        } catch (InvalidProtocolBufferException e) {
            e.printStackTrace();
            return Optional.empty();
        }
    }
}
