package uk.gov.di.authentication.sharedtest.extensions;

import com.google.gson.JsonParser;
import uk.gov.di.audit.AuditPayload;
import uk.gov.di.audit.helper.AuditEventHelper;
import uk.gov.di.authentication.sharedtest.httpstub.RecordedRequest;

import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

public class AuditSnsTopicExtension extends SnsTopicExtension {

    public static final int SNS_TIMEOUT = 10; // In seconds.

    public AuditSnsTopicExtension(String topicNameSuffix) {
        super(topicNameSuffix);
    }

    public List<AuditPayload.AuditEvent> getAuditEvents() {
        return getRecordedRequests().stream()
                .map(RecordedRequest::getEntity)
                .map(AuditSnsTopicExtension::mapRequest)
                .collect(Collectors.toList());
    }

    private static AuditPayload.AuditEvent mapRequest(String json) {
        String message = JsonParser.parseString(json).getAsJsonObject().get("Message").getAsString();
        byte[] decodedBytes = Base64.getDecoder().decode(message);
        Optional<AuditPayload.SignedAuditEvent> signedAuditEvent =
                AuditEventHelper.parseToSignedAuditEvent(decodedBytes);
        Optional<AuditPayload.AuditEvent> auditEvent =
                AuditEventHelper.extractPayload(signedAuditEvent);

        return auditEvent.get();
    }
}
