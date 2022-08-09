package uk.gov.di.authentication.shared.services;

import com.amazonaws.services.kms.model.SignRequest;
import com.amazonaws.services.kms.model.SignResult;
import com.google.protobuf.InvalidProtocolBufferException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.MockitoAnnotations;
import uk.gov.di.audit.AuditPayload.SignedAuditEvent;
import uk.gov.di.authentication.shared.domain.AuditableEvent;
import uk.gov.di.authentication.sharedtest.matchers.JsonMatcher;

import java.nio.ByteBuffer;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.Base64;
import java.util.Map;
import java.util.function.Predicate;

import static java.util.Map.entry;
import static java.util.Map.ofEntries;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;
import static uk.gov.di.authentication.shared.services.AuditServiceTest.TestEvents.TEST_EVENT_ONE;
import static uk.gov.di.authentication.sharedtest.matchers.AuditMessageMatcher.hasClientId;
import static uk.gov.di.authentication.sharedtest.matchers.AuditMessageMatcher.hasEmail;
import static uk.gov.di.authentication.sharedtest.matchers.AuditMessageMatcher.hasEventName;
import static uk.gov.di.authentication.sharedtest.matchers.AuditMessageMatcher.hasIpAddress;
import static uk.gov.di.authentication.sharedtest.matchers.AuditMessageMatcher.hasMetadataPair;
import static uk.gov.di.authentication.sharedtest.matchers.AuditMessageMatcher.hasPersistentSessionId;
import static uk.gov.di.authentication.sharedtest.matchers.AuditMessageMatcher.hasPhoneNumber;
import static uk.gov.di.authentication.sharedtest.matchers.AuditMessageMatcher.hasRequestId;
import static uk.gov.di.authentication.sharedtest.matchers.AuditMessageMatcher.hasSessionId;
import static uk.gov.di.authentication.sharedtest.matchers.AuditMessageMatcher.hasSubjectId;
import static uk.gov.di.authentication.sharedtest.matchers.AuditMessageMatcher.hasTimestamp;

class AuditServiceTest {

    private static final String FIXED_TIMESTAMP = "2021-09-01T22:10:00.012Z";
    private static final Clock FIXED_CLOCK =
            Clock.fixed(Instant.parse(FIXED_TIMESTAMP), ZoneId.of("UTC"));

    private final SnsService snsService = mock(SnsService.class);
    private final KmsConnectionService kmsConnectionService = mock(KmsConnectionService.class);
    private final AwsSqsClient awsSqsClient = mock(AwsSqsClient.class);

    @Captor private ArgumentCaptor<String> messageCaptor;

    enum TestEvents implements AuditableEvent {
        TEST_EVENT_ONE;

        public AuditableEvent parseFromName(String name) {
            return valueOf(name);
        }
    }

    @BeforeEach
    void beforeEach() {
        var stubSignature = new SignResult().withSignature(ByteBuffer.wrap("signature".getBytes()));
        when(kmsConnectionService.sign(any(SignRequest.class))).thenReturn(stubSignature);
        MockitoAnnotations.openMocks(this);
    }

    @AfterEach
    void afterEach() {
        verifyNoMoreInteractions(snsService);
    }

    @Test
    void shouldLogAuditEvent() {
        var auditService =
                new AuditService(
                        FIXED_CLOCK,
                        snsService,
                        kmsConnectionService,
                        mock(ConfigurationService.class),
                        awsSqsClient);

        auditService.submitAuditEvent(
                TEST_EVENT_ONE,
                "request-id",
                "session-id",
                "client-id",
                "subject-id",
                "email",
                "ip-address",
                "phone-number",
                "persistent-session-id");

        verify(snsService).publishAuditMessage(messageCaptor.capture());
        var serialisedAuditMessage = messageCaptor.getValue();

        assertThat(serialisedAuditMessage, hasTimestamp(FIXED_TIMESTAMP));
        assertThat(serialisedAuditMessage, hasEventName(TEST_EVENT_ONE.toString()));
        assertThat(serialisedAuditMessage, hasRequestId("request-id"));
        assertThat(serialisedAuditMessage, hasSessionId("session-id"));
        assertThat(serialisedAuditMessage, hasPersistentSessionId("persistent-session-id"));
        assertThat(serialisedAuditMessage, hasClientId("client-id"));
        assertThat(serialisedAuditMessage, hasSubjectId("subject-id"));
        assertThat(serialisedAuditMessage, hasEmail("email"));
        assertThat(serialisedAuditMessage, hasIpAddress("ip-address"));
        assertThat(serialisedAuditMessage, hasPhoneNumber("phone-number"));

        verify(awsSqsClient)
                .send(
                        hasFields(
                                ofEntries(
                                        entry("event_name", "AUTH_TEST_EVENT_ONE"),
                                        entry("timestamp", "1630534200"))));
    }

    @Test
    void shouldSignAuditEventPayload() throws InvalidProtocolBufferException {
        var auditService =
                new AuditService(
                        FIXED_CLOCK,
                        snsService,
                        kmsConnectionService,
                        mock(ConfigurationService.class),
                        awsSqsClient);

        var signingRequestCaptor = ArgumentCaptor.forClass(SignRequest.class);

        auditService.submitAuditEvent(
                TEST_EVENT_ONE,
                "request-id",
                "session-id",
                "client-id",
                "subject-id",
                "email",
                "ip-address",
                "persistent-session-id",
                "phone-number");

        verify(kmsConnectionService).sign(signingRequestCaptor.capture());
        verify(snsService).publishAuditMessage(messageCaptor.capture());

        SignedAuditEvent event =
                SignedAuditEvent.parseFrom(Base64.getDecoder().decode(messageCaptor.getValue()));

        assertThat(
                event.getPayload().toByteArray(),
                is(signingRequestCaptor.getValue().getMessage().array()));
        assertThat(event.getSignature().toByteArray(), is("signature".getBytes()));
    }

    @Test
    void shouldLogAuditEventWithMetadataPairsAttached() {
        var auditService =
                new AuditService(
                        FIXED_CLOCK,
                        snsService,
                        kmsConnectionService,
                        mock(ConfigurationService.class),
                        awsSqsClient);

        auditService.submitAuditEvent(
                TEST_EVENT_ONE,
                "request-id",
                "session-id",
                "client-id",
                "subject-id",
                "email",
                "ip-address",
                "phone-number",
                "persistent-session-id",
                pair("key", "value"),
                pair("key2", "value2"));

        verify(snsService).publishAuditMessage(messageCaptor.capture());
        var serialisedAuditMessage = messageCaptor.getValue();

        assertThat(serialisedAuditMessage, hasTimestamp(FIXED_TIMESTAMP));
        assertThat(serialisedAuditMessage, hasEventName(TEST_EVENT_ONE.toString()));
        assertThat(serialisedAuditMessage, hasMetadataPair(pair("key", "value")));
        assertThat(serialisedAuditMessage, hasMetadataPair(pair("key2", "value2")));
    }

    private String hasFields(Map<String, String> fields) {
        return argThat(
                argument -> {
                    var payload = JsonMatcher.asJson(argument).getAsJsonObject();

                    Predicate<Map.Entry<String, String>> matchEntry =
                            (entry) -> {
                                var value = payload.get(entry.getKey());

                                if ("timestamp".equals(entry.getKey())) {
                                    return Long.parseLong(entry.getValue()) == value.getAsLong();
                                } else {
                                    return entry.getValue().equals(value.getAsString());
                                }
                            };

                    return fields.entrySet().stream().allMatch(matchEntry);
                });
    }
}
