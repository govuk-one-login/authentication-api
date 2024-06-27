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
import java.util.Optional;

import static java.util.function.Predicate.not;
import static uk.gov.di.audit.TxmaAuditEvent.auditEventWithTime;

public class AuditService {
    private static final Logger LOG = LogManager.getLogger(AuditService.class);

    public static final String UNKNOWN = "";
    public static final String COMPONENT_ID = "AUTH";

    private final Clock clock;
    private final AwsSqsClient txmaQueueClient;

    public AuditService(Clock clock, AwsSqsClient txmaQueueClient) {
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
            Optional<String> txmaAuditEncoded,
            TxmaAuditEvent txmaAuditEvent,
            MetadataPair... metadataPairs) {
        Arrays.stream(metadataPairs)
                .filter(MetadataPair::isRestricted)
                .forEach(pair -> txmaAuditEvent.addRestricted(pair.key(), pair.value()));

        txmaAuditEncoded.ifPresentOrElse(
                s -> {
                    if (!s.isEmpty()) {
                        txmaAuditEvent.addRestricted("device_information", Map.of("encoded", s));
                    } else {
                        LOG.warn("Encoded device information for audit event present but empty.");
                    }
                },
                () -> LOG.warn("Encoded device information for audit event is not present."));
    }

    private static void addExtensionSectionToAuditEvent(
            TxmaAuditUser user, TxmaAuditEvent txmaAuditEvent, MetadataPair... metadataPairs) {
        Arrays.stream(metadataPairs)
                .filter(not(MetadataPair::isRestricted))
                .forEach(pair -> txmaAuditEvent.addExtension(pair.key(), pair.value()));

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
            AuditableEvent event, AuditContext auditContext, MetadataPair... metadataPairs) {

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

        addRestrictedSectionToAuditEvent(
                auditContext.txmaAuditEncoded(), txmaAuditEvent, metadataPairs);
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
                        persistentSessionId,
                        restrictedSection.encoded);

        submitAuditEvent(event, auditContext, metadataPairs);
    }

    public record MetadataPair(String key, Object value, boolean isRestricted) {
        public static MetadataPair pair(String key, Object value) {
            return new MetadataPair(key, value, false);
        }

        public static MetadataPair pair(String key, Object value, boolean restricted) {
            return new MetadataPair(key, value, restricted);
        }
    }
}
