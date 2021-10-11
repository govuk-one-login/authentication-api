package uk.gov.di.authentication.audit.lambda;

import com.amazonaws.services.lambda.runtime.events.SNSEvent;
import com.amazonaws.services.lambda.runtime.events.SNSEvent.SNS;
import com.amazonaws.services.lambda.runtime.events.SNSEvent.SNSRecord;
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

public class BaseAuditLambdaTest {

    private final KmsConnectionService kms = mock(KmsConnectionService.class);
    private final ConfigurationService config = mock(ConfigurationService.class);

    @Test
    void handlesRequestsAppropriately() {
        when(config.getAuditSigningKeyAlias()).thenReturn("key_alias");
        when(kms.validateSignature(any(ByteBuffer.class), any(ByteBuffer.class), anyString()))
                .thenReturn(true);

        var baseHandler =
                new BaseAuditHandler(kms, config) {
                    @Override
                    void handleAuditEvent(AuditEvent auditEvent) {
                        assertThat(auditEvent.getEventId(), is("foo"));
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

    private SNSEvent inputEvent(SignedAuditEvent payload) {
        return Optional.of(payload)
                .map(AbstractMessageLite::toByteArray)
                .map(Base64.getEncoder()::encodeToString)
                .map(new SNS()::withMessage)
                .map(new SNSRecord()::withSns)
                .map(List::of)
                .map(new SNSEvent()::withRecords)
                .get();
    }
}
