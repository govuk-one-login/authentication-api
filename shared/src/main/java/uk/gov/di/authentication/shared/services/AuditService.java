package uk.gov.di.authentication.shared.services;

import org.apache.logging.log4j.ThreadContext;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.audit.TxmaAuditUser;
import uk.gov.di.authentication.shared.domain.AuditableEvent;
import uk.gov.di.authentication.shared.helpers.PhoneNumberHelper;

import java.time.Clock;
import java.util.Arrays;
import java.util.Date;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Consumer;

import static java.util.function.Predicate.not;
import static uk.gov.di.audit.TxmaAuditEvent.auditEventWithTime;
import static uk.gov.di.authentication.shared.helpers.AuditHelper.AuditField.TXMA_ENCODED_HEADER;

public class AuditService {

    public static final String UNKNOWN = "";

    private final Clock clock;
    private final ConfigurationService configurationService;
    private final AwsSqsClient txmaQueueClient;
    private final String COMPONENT_ID = "AUTH";

    public AuditService(
            Clock clock, ConfigurationService configurationService, AwsSqsClient txmaQueueClient) {
        this.clock = clock;
        this.configurationService = configurationService;
        this.txmaQueueClient = txmaQueueClient;
    }

    public AuditService(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        this.clock = Clock.systemUTC();
        this.txmaQueueClient =
                new AwsSqsClient(
                        configurationService.getAwsRegion(),
                        configurationService.getTxmaAuditQueueUrl(),
                        configurationService.getLocalstackEndpointUri());
    }

    public void submitAuditEvent(AuditableEvent event, AuditContext auditContext) {
        submitAuditEvent(
                event,
                auditContext.getClientSessionId(),
                auditContext.getSessionId(),
                auditContext.getClientId(),
                auditContext.getSubjectId(),
                auditContext.getEmail(),
                auditContext.getIpAddress(),
                auditContext.getPhoneNumber(),
                auditContext.getPersistentSessionId(),
                auditContext.getMetadataPairs());
    }

    public void submitAuditEvent(
            AuditableEvent event,
            String clientId,
            TxmaAuditUser user,
            MetadataPair... metadataPairs) {
        var txmaAuditEvent =
                auditEventWithTime(event, () -> Date.from(clock.instant()))
                        .withClientId(clientId)
                        .withComponentId(COMPONENT_ID)
                        .withUser(user);

        if (configurationService.isTxmaAuditEncodedEnabled()
                && ThreadContext.get(TXMA_ENCODED_HEADER.getFieldName()) != null) {
            txmaAuditEvent.addRestricted(
                    "device_information",
                    Map.of("encoded", ThreadContext.get(TXMA_ENCODED_HEADER.getFieldName())));
        }

        Arrays.stream(metadataPairs)
                .forEach(pair -> txmaAuditEvent.addExtension(pair.getKey(), pair.getValue()));

        Optional.ofNullable(user.getPhone())
                .filter(not(String::isBlank))
                .flatMap(PhoneNumberHelper::maybeGetCountry)
                .ifPresent(
                        country ->
                                txmaAuditEvent.addExtension("phone_number_country_code", country));

        txmaQueueClient.send(txmaAuditEvent.serialize());
    }

    public void submitAuditEvent(
            AuditableEvent event,
            String clientSessionId,
            String sessionId,
            String clientId,
            String subjectId,
            String email,
            String ipAddress,
            String phoneNumber,
            String persistentSessionId,
            MetadataPair... metadataPairs) {

        var user =
                TxmaAuditUser.user()
                        .withUserId(subjectId)
                        .withPhone(phoneNumber)
                        .withEmail(email)
                        .withIpAddress(ipAddress)
                        .withSessionId(sessionId)
                        .withPersistentSessionId(persistentSessionId)
                        .withGovukSigninJourneyId(clientSessionId);

        submitAuditEvent(event, clientId, user, metadataPairs);
    }

    public static class MetadataPair {
        private final String key;
        private final Object value;

        private MetadataPair(String key, Object value) {
            this.key = key;
            this.value = value;
        }

        public static MetadataPair pair(String key, Object value) {
            return new MetadataPair(key, value);
        }

        public String getKey() {
            return key;
        }

        public Object getValue() {
            return value;
        }

        @Override
        public String toString() {
            return String.format("[%s: %s]", key, value);
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            MetadataPair that = (MetadataPair) o;
            return Objects.equals(key, that.key) && Objects.equals(value, that.value);
        }

        @Override
        public int hashCode() {
            return Objects.hash(key, value);
        }
    }

    static void addField(String value, Consumer<String> setter) {
        Optional.ofNullable(value).ifPresent(setter);
    }
}
