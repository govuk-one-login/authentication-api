package uk.gov.di.authentication.shared.services;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.audit.TxmaAuditEvent;
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

public class AuditService {
    private static final Logger LOG = LogManager.getLogger(AuditService.class);

    public static final String UNKNOWN = "";
    public static final String COMPONENT_ID = "AUTH";

    private final Clock clock;
    private final AwsSqsClient txmaQueueClient;

    public AuditService(
            Clock clock, ConfigurationService configurationService, AwsSqsClient txmaQueueClient) {
        this.clock = clock;
        this.txmaQueueClient = txmaQueueClient;
    }

    public AuditService(ConfigurationService configurationService) {
        this.clock = Clock.systemUTC();
        this.txmaQueueClient =
                new AwsSqsClient(
                        configurationService.getAwsRegion(),
                        configurationService.getTxmaAuditQueueUrl(),
                        configurationService.getLocalstackEndpointUri());
    }

    private static void addRestrictedSectionToAuditEvent(
            RestrictedSection restrictedSection,
            TxmaAuditEvent txmaAuditEvent,
            MetadataPair... metadataPairs) {
        Arrays.stream(metadataPairs)
                .forEach(
                        pair -> {
                            if (Boolean.TRUE.equals(pair.isRestricted())) {
                                txmaAuditEvent.addRestricted(pair.getKey(), pair.getValue());
                            }
                        });

        restrictedSection
                .encoded()
                .ifPresentOrElse(
                        s -> {
                            if (!s.isEmpty()) {
                                txmaAuditEvent.addRestricted(
                                        "device_information", Map.of("encoded", s));
                            } else {
                                LOG.warn(
                                        "Encoded device information for audit event present but empty.");
                            }
                        },
                        () ->
                                LOG.warn(
                                        "Encoded device information for audit event is not present."));
    }

    private static void addExtensionSectionToAuditEvent(
            TxmaAuditUser user, TxmaAuditEvent txmaAuditEvent, MetadataPair... metadataPairs) {
        Arrays.stream(metadataPairs)
                .forEach(
                        pair -> {
                            if (Boolean.FALSE.equals(pair.isRestricted())) {
                                txmaAuditEvent.addExtension(pair.getKey(), pair.getValue());
                            }
                        });
        Optional.ofNullable(user.getPhone())
                .filter(not(String::isBlank))
                .flatMap(PhoneNumberHelper::maybeGetCountry)
                .ifPresent(
                        country ->
                                txmaAuditEvent.addExtension("phone_number_country_code", country));
    }

    public record RestrictedSection(Optional<String> encoded) {
        public static final RestrictedSection empty = new RestrictedSection(Optional.empty());
    }

    public void submitAuditEvent(
            AuditableEvent event,
            AuditContext auditContext,
            RestrictedSection restrictedSection,
            MetadataPair... metadataPairs) {

        var user =
                TxmaAuditUser.user()
                        .withUserId(auditContext.subjectId())
                        .withPhone(auditContext.phoneNumber())
                        .withEmail(auditContext.email())
                        .withIpAddress(auditContext.ipAddress())
                        .withSessionId(auditContext.sessionId())
                        .withPersistentSessionId(auditContext.persistentSessionId())
                        .withGovukSigninJourneyId(auditContext.clientSessionId());

        var txmaAuditEvent =
                auditEventWithTime(event, () -> Date.from(clock.instant()))
                        .withClientId(auditContext.clientId())
                        .withComponentId(COMPONENT_ID)
                        .withUser(user);

        addRestrictedSectionToAuditEvent(restrictedSection, txmaAuditEvent, metadataPairs);
        addExtensionSectionToAuditEvent(user, txmaAuditEvent, metadataPairs);

        txmaQueueClient.send(txmaAuditEvent.serialize());
    }

    public void submitAuditEvent(
            AuditableEvent event,
            String clientId,
            String clientSessionId,
            String sessionId,
            String subjectId,
            String email,
            String ipAddress,
            String phoneNumber,
            String persistentSessionId,
            RestrictedSection restrictedSection,
            MetadataPair... metadataPairs) {

        var auditContext =
                new AuditContext(
                        clientId,
                        clientSessionId,
                        sessionId,
                        subjectId,
                        email,
                        ipAddress,
                        phoneNumber,
                        persistentSessionId);

        submitAuditEvent(event, auditContext, restrictedSection, metadataPairs);
    }

    public static class MetadataPair {
        private final String key;
        private final Object value;
        private final Boolean restricted;

        private MetadataPair(String key, Object value) {
            this(key, value, false);
        }

        private MetadataPair(String key, Object value, Boolean restricted) {
            this.key = key;
            this.value = value;
            this.restricted = restricted;
        }

        public static MetadataPair pair(String key, Object value) {
            return new MetadataPair(key, value, false);
        }

        public static MetadataPair pair(String key, Object value, Boolean restricted) {
            return new MetadataPair(key, value, restricted);
        }

        public String getKey() {
            return key;
        }

        public Object getValue() {
            return value;
        }

        public Boolean isRestricted() {
            return restricted;
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
            return Objects.equals(key, that.key)
                    && Objects.equals(value, that.value)
                    && Objects.equals(restricted, that.restricted);
        }

        @Override
        public int hashCode() {
            return Objects.hash(key, value, restricted);
        }
    }

    static void addField(String value, Consumer<String> setter) {
        Optional.ofNullable(value).ifPresent(setter);
    }
}
