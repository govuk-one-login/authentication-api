package uk.gov.di.authentication.audit.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.SQSEvent;
import com.amazonaws.services.lambda.runtime.events.SQSEvent.SQSMessage;
import com.google.gson.JsonParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.audit.AuditPayload.AuditEvent;
import uk.gov.di.audit.AuditPayload.SignedAuditEvent;
import uk.gov.di.authentication.audit.helper.AuditEventHelper;
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

    public StorageSQSAuditHandler(
            KmsConnectionService kmsConnectionService, ConfigurationService service) {
        this.kmsConnectionService = kmsConnectionService;
        this.service = service;
    }

    public StorageSQSAuditHandler() {
        this.service = new ConfigurationService();
        this.kmsConnectionService = new KmsConnectionService(service);
    }

    @Override
    public Object handleRequest(SQSEvent input, Context context) {
        LOG.info("Processing {} events from queue", input.getRecords().size());
        var auditMessages =
                input.getRecords().stream()
                        .peek(record -> LOG.info("Processing record {}", record.getMessageId()))
                        .map(SQSMessage::getBody)
                        .map(this::readAsJson)
                        .map(Base64.getDecoder()::decode)
                        .peek(payload -> LOG.info("Extracted payload: length {}", payload.length))
                        .map(AuditEventHelper::parseToSignedAuditEvent)
                        .filter(this::validateSignature)
                        .map(AuditEventHelper::extractPayload)
                        .filter(Optional::isPresent)
                        .map(Optional::get)
                        .collect(Collectors.toList());

        LOG.info("Consuming {} audit messages", auditMessages.size());

        this.handleAuditEvent(auditMessages);

        return null;
    }

    private String readAsJson(String snsMessage) {
        return JsonParser.parseString(snsMessage).getAsJsonObject().get("Message").getAsString();
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

    private boolean validateSignature(Optional<SignedAuditEvent> event) {
        if (event.isEmpty()) {
            LOG.error("Missing payload could not validate signature");
            return false;
        }

        LOG.info("Validating signature");

        return kmsConnectionService.validateSignature(
                event.get().getSignature().asReadOnlyByteBuffer(),
                event.get().getPayload().asReadOnlyByteBuffer(),
                service.getAuditSigningKeyAlias());
    }
}
