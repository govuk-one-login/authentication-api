package uk.gov.di.authentication.shared.services;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
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

    public void submitAuditEvent(
            AuditableEvent event,
            String clientId,
            TxmaAuditUser user,
            RestrictedSection restrictedSection,
            MetadataPair... metadataPairs) {
        var txmaAuditEvent =
                auditEventWithTime(event, () -> Date.from(clock.instant()))
                        .withClientId(clientId)
                        .withComponentId(COMPONENT_ID)
                        .withUser(user);

        Arrays.stream(metadataPairs)
                .forEach(
                        pair -> {
                            if (pair.isRestricted()) {
                                txmaAuditEvent.addRestricted(pair.getKey(), pair.getValue());
                            } else {
                                txmaAuditEvent.addExtension(pair.getKey(), pair.getValue());
                            }
                        });

        restrictedSection
                .encoded
                .filter(s -> !s.isEmpty())
                .ifPresentOrElse(
                        s ->
                                txmaAuditEvent.addRestricted(
                                        "device_information", Map.of("encoded", s)),
                        () -> {
                            if (restrictedSection.encoded.isPresent()) {
                                LOG.warn("encoded present but empty");
                            } else {
                                LOG.warn("encoded not present");
                            }
                        });

        Optional.ofNullable(user.getPhone())
                .filter(not(String::isBlank))
                .flatMap(PhoneNumberHelper::maybeGetCountry)
                .ifPresent(
                        country ->
                                txmaAuditEvent.addExtension("phone_number_country_code", country));

        txmaQueueClient.send(txmaAuditEvent.serialize());
    }

    public record RestrictedSection(Optional<String> encoded) {
        public static final RestrictedSection empty = new RestrictedSection(Optional.empty());
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

        var user =
                TxmaAuditUser.user()
                        .withUserId(subjectId)
                        .withPhone(phoneNumber)
                        .withEmail(email)
                        .withIpAddress(ipAddress)
                        .withSessionId(sessionId)
                        .withPersistentSessionId(persistentSessionId)
                        .withGovukSigninJourneyId(clientSessionId);

        submitAuditEvent(event, clientId, user, restrictedSection, metadataPairs);
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
