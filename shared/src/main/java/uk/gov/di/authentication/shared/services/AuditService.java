package uk.gov.di.authentication.shared.services;

import uk.gov.di.audit.TxmaAuditUser;
import uk.gov.di.authentication.shared.domain.AuditableEvent;

import java.time.Clock;
import java.util.Arrays;
import java.util.Date;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Consumer;

import static uk.gov.di.audit.TxmaAuditEvent.auditEventWithTime;

public class AuditService {

    public static final String UNKNOWN = "";

    private final Clock clock;
    private final SnsService snsService;
    private final KmsConnectionService kmsConnectionService;
    private final ConfigurationService configurationService;
    private final AwsSqsClient txmaQueueClient;

    public AuditService(
            Clock clock,
            SnsService snsService,
            KmsConnectionService kmsConnectionService,
            ConfigurationService configurationService,
            AwsSqsClient txmaQueueClient) {
        this.clock = clock;
        this.snsService = snsService;
        this.kmsConnectionService = kmsConnectionService;
        this.configurationService = configurationService;
        this.txmaQueueClient = txmaQueueClient;
    }

    public AuditService(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        this.clock = Clock.systemUTC();
        this.snsService = new SnsService(configurationService);
        this.kmsConnectionService =
                new KmsConnectionService(
                        configurationService.getLocalstackEndpointUri(),
                        configurationService.getAwsRegion(),
                        configurationService.getAuditSigningKeyAlias());

        this.txmaQueueClient =
                configurationService.isTxmaAuditEnabled()
                        ? new AwsSqsClient(
                                configurationService.getAwsRegion(),
                                configurationService.getTxmaAuditQueueUrl(),
                                configurationService.getLocalstackEndpointUri())
                        : new AwsSqsClient.NoOpSqsClient();
    }

    public void submitAuditEvent(
            AuditableEvent event,
            String requestId,
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
                        .withPersistentSessionId(persistentSessionId);

        var txmaAuditEvent =
                auditEventWithTime(event, () -> Date.from(clock.instant()))
                        .withClientId(clientId)
                        .withComponentId(configurationService.getOidcApiBaseURL().orElse("UNKNOWN"))
                        .withUser(user);

        Arrays.stream(metadataPairs)
                .forEach(pair -> txmaAuditEvent.addExtension(pair.getKey(), pair.getValue()));

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

    static void addField(String value, Consumer<String> setter) {
        Optional.ofNullable(value).ifPresent(setter);
    }
}
