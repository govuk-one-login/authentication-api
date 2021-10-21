package uk.gov.di.authentication.audit.lambda;

import com.amazonaws.services.lambda.runtime.events.SQSEvent;
import com.amazonaws.services.lambda.runtime.events.SQSEvent.SQSMessage;
import com.google.gson.Gson;
import com.google.protobuf.AbstractMessageLite;
import com.google.protobuf.ByteString;
import org.junit.jupiter.api.Test;
import uk.gov.di.audit.AuditPayload.AuditEvent;
import uk.gov.di.audit.AuditPayload.SignedAuditEvent;
import uk.gov.di.authentication.audit.services.S3Service;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.KmsConnectionService;

import java.nio.ByteBuffer;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class StorageSQSAuditHandlerTest {

    private final KmsConnectionService kms = mock(KmsConnectionService.class);
    private final ConfigurationService config = mock(ConfigurationService.class);
    private final S3Service s3Service = mock(S3Service.class);

    @Test
    void handlesRequestsAppropriately() {
        when(config.getAuditSigningKeyAlias()).thenReturn("key_alias");
        when(kms.validateSignature(any(ByteBuffer.class), any(ByteBuffer.class), anyString()))
                .thenReturn(true);

        var baseHandler =
                new StorageSQSAuditHandler(kms, config, s3Service) {
                    @Override
                    void handleAuditEvent(List<AuditEvent> auditEvents) {
                        assertThat(auditEvents.size(), is(1));
                    }
                };

        var payload = payloadWithEventId("foo");

        baseHandler.handleRequest(inputEvent(payload), null);
    }

    @Test
    void collectsPayloadsAndWritesThemToS3() {
        when(config.getAuditSigningKeyAlias()).thenReturn("key_alias");
        when(kms.validateSignature(any(ByteBuffer.class), any(ByteBuffer.class), anyString()))
                .thenReturn(true);

        var handler = new StorageSQSAuditHandler(kms, config, s3Service);

        var payloads = List.of(payloadWithEventId("foo"), payloadWithEventId("bar"));

        handler.handleRequest(inputEvent(payloads), null);

        verify(s3Service).storeRecords("{\"eventId\":\"foo\"}\n{\"eventId\":\"bar\"}");
    }

    private SignedAuditEvent payloadWithEventId(String eventId) {
        return SignedAuditEvent.newBuilder()
                .setSignature(ByteString.copyFrom("signature".getBytes()))
                .setPayload(AuditEvent.newBuilder().setEventId(eventId).build().toByteString())
                .build();
    }

    private SQSEvent inputEvent(SignedAuditEvent payload) {
        return inputEvent(Collections.singletonList(payload));
    }

    private SQSEvent inputEvent(List<SignedAuditEvent> payload) {
        var messages =
                payload.stream()
                        .map(AbstractMessageLite::toByteArray)
                        .map(Base64.getEncoder()::encodeToString)
                        .map(encodedPayload -> new Gson().toJson(Map.of("Message", encodedPayload)))
                        .map(
                                body -> {
                                    var message = new SQSMessage();
                                    message.setBody(body);

                                    return message;
                                })
                        .collect(Collectors.toList());

        var event = new SQSEvent();
        event.setRecords(messages);

        return event;
    }
}
