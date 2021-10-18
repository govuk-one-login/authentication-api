package uk.gov.di.authentication.audit.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.SQSEvent;
import com.amazonaws.services.lambda.runtime.events.SQSEvent.SQSMessage;
import com.google.protobuf.InvalidProtocolBufferException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.audit.AuditPayload.AuditEvent;
import uk.gov.di.audit.AuditPayload.SignedAuditEvent;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.KmsConnectionService;

import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

public class StorageSQSAuditHandler implements RequestHandler<SQSEvent, Object> {

    protected final Logger LOG = LoggerFactory.getLogger(getClass());
    private final KmsConnectionService kmsConnectionService;
    private final ConfigurationService service;

    StorageSQSAuditHandler(
            KmsConnectionService kmsConnectionService, ConfigurationService service) {
        this.kmsConnectionService = kmsConnectionService;
        this.service = service;
    }

    StorageSQSAuditHandler() {
        this.service = new ConfigurationService();
        this.kmsConnectionService = new KmsConnectionService(service);
    }

    @Override
    public Object handleRequest(SQSEvent input, Context context) {
        var auditMessages =
                input.getRecords().stream()
                        .map(SQSMessage::getBody)
                        .map(Base64.getDecoder()::decode)
                        .map(this::parseToSignedAuditEvent)
                        .filter(this::validateSignature)
                        .map(this::extractPayload)
                        .filter(Optional::isPresent)
                        .map(Optional::get)
                        .collect(Collectors.toList());

        LOG.info("Consuming {} audit messages", auditMessages.size());

        this.handleAuditEvent(auditMessages);

        return null;
    }

    void handleAuditEvent(List<AuditEvent> auditEvent) {
        auditEvent.forEach(
                event ->
                        LOG.info(
                                "Processing event({}, {}, {})",
                                event.getEventId(),
                                event.getEventName(),
                                event.getClientId()));
    }

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
