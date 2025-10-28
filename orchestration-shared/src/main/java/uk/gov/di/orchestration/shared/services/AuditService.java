package uk.gov.di.orchestration.shared.services;

import org.apache.logging.log4j.ThreadContext;
import uk.gov.di.orchestration.audit.AuditContext;
import uk.gov.di.orchestration.audit.TxmaAuditUser;
import uk.gov.di.orchestration.shared.api.OidcAPI;
import uk.gov.di.orchestration.shared.domain.AuditableEvent;
import uk.gov.di.orchestration.shared.helpers.PhoneNumberHelper;

import java.time.Clock;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import static java.util.function.Predicate.not;
import static uk.gov.di.orchestration.audit.TxmaAuditEvent.auditEventWithTime;
import static uk.gov.di.orchestration.shared.helpers.AuditHelper.AuditField.TXMA_ENCODED_HEADER;

public class AuditService {

    public static final String UNKNOWN = "";

    private final Clock clock;
    private final OidcAPI oidcApi;
    private final AwsSqsClient txmaQueueClient;

    public AuditService(Clock clock, OidcAPI oidcApi, AwsSqsClient txmaQueueClient) {
        this.clock = clock;
        this.oidcApi = oidcApi;
        this.txmaQueueClient = txmaQueueClient;
    }

    public AuditService(ConfigurationService configurationService) {
        this.oidcApi = new OidcAPI(configurationService);
        this.clock = Clock.systemUTC();
        this.txmaQueueClient =
                new AwsSqsClient(
                        configurationService.getAwsRegion(),
                        configurationService.getTxmaAuditQueueUrl(),
                        configurationService.getLocalstackEndpointUri());
    }

    public void submitAuditEvent(AuditableEvent event, AuditContext auditContext) {

        var user =
                TxmaAuditUser.user()
                        .withUserId(auditContext.subjectId())
                        .withPhone(auditContext.phoneNumber())
                        .withEmail(auditContext.email())
                        .withIpAddress(auditContext.ipAddress())
                        .withSessionId(auditContext.sessionId())
                        .withPersistentSessionId(auditContext.persistentSessionId())
                        .withGovukSigninJourneyId(auditContext.clientSessionId());

        submitAuditEvent(event, auditContext.clientId(), user, auditContext.metadataPairs());
    }

    public void submitAuditEvent(
            AuditableEvent event,
            String clientId,
            TxmaAuditUser user,
            MetadataPair... metadataPairs) {
        submitAuditEvent(event, clientId, user, Arrays.asList(metadataPairs));
    }

    public void submitAuditEvent(
            AuditableEvent event,
            String clientId,
            TxmaAuditUser user,
            List<MetadataPair> metadataPairs) {
        var txmaAuditEvent =
                auditEventWithTime(event, () -> Date.from(clock.instant()))
                        .withClientId(clientId)
                        .withComponentId(oidcApi.baseURI().toString())
                        .withUser(user);

        if (ThreadContext.get(TXMA_ENCODED_HEADER.getFieldName()) != null) {
            txmaAuditEvent.addRestricted(
                    "device_information",
                    Map.of("encoded", ThreadContext.get(TXMA_ENCODED_HEADER.getFieldName())));
        }

        metadataPairs.forEach(pair -> txmaAuditEvent.addExtension(pair.getKey(), pair.getValue()));

        Optional.ofNullable(user.phone())
                .filter(not(String::isBlank))
                .flatMap(PhoneNumberHelper::maybeGetCountry)
                .ifPresent(
                        country ->
                                txmaAuditEvent.addExtension("phone_number_country_code", country));

        txmaQueueClient.send(txmaAuditEvent.serialize());
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
}
