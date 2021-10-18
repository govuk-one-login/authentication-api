package uk.gov.di.authentication.audit.lambda;

import com.amazonaws.services.lambda.runtime.events.SQSEvent;
import com.amazonaws.services.lambda.runtime.events.SQSEvent.SQSMessage;
import com.google.protobuf.AbstractMessageLite;
import com.google.protobuf.ByteString;
import org.junit.jupiter.api.Test;
import uk.gov.di.audit.AuditPayload.AuditEvent;
import uk.gov.di.audit.AuditPayload.SignedAuditEvent;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.KmsConnectionService;

import java.nio.ByteBuffer;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class StorageSQSAuditHandlerTest {

    private final KmsConnectionService kms = mock(KmsConnectionService.class);
    private final ConfigurationService config = mock(ConfigurationService.class);

    @Test
    void handlesRequestsAppropriately() {
        when(config.getAuditSigningKeyAlias()).thenReturn("key_alias");
        when(kms.validateSignature(any(ByteBuffer.class), any(ByteBuffer.class), anyString()))
                .thenReturn(true);

        var baseHandler =
                new StorageSQSAuditHandler(kms, config) {
                    @Override
                    void handleAuditEvent(List<AuditEvent> auditEvents) {
                        assertThat(auditEvents.size(), is(1));
                    }
                };

        var payload =
                SignedAuditEvent.newBuilder()
                        .setSignature(ByteString.copyFrom("signature".getBytes()))
                        .setPayload(
                                AuditEvent.newBuilder().setEventId("foo").build().toByteString())
                        .build();

        baseHandler.handleRequest(inputEvent(payload), null);
    }

    private SQSEvent inputEvent(SignedAuditEvent payload) {
        return Optional.of(payload)
                .map(AbstractMessageLite::toByteArray)
                .map(Base64.getEncoder()::encodeToString)
                .map(
                        body -> {
                            var message = new SQSMessage();
                            message.setBody(body);

                            var event = new SQSEvent();
                            event.setRecords(List.of(message));

                            return event;
                        })
                .get();
    }
}
