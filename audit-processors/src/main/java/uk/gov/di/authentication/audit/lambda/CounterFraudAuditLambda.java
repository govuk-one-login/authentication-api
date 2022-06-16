package uk.gov.di.authentication.audit.lambda;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.ObjectMessage;
import uk.gov.di.audit.AuditPayload.AuditEvent;
import uk.gov.di.audit.AuditPayload.AuditEvent.User;
import uk.gov.di.authentication.audit.configuration.TXMAConfiguration;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.KmsConnectionService;

import java.util.HashMap;
import java.util.Optional;

import static org.apache.commons.codec.binary.Hex.encodeHexString;
import static uk.gov.di.authentication.audit.helper.HmacSha256Helper.hmacSha256;

public class CounterFraudAuditLambda extends BaseAuditHandler {

    private static final Logger LOG = LogManager.getLogger(CounterFraudAuditLambda.class);
    private final Optional<TXMAConfiguration> txmaConfiguration;

    public CounterFraudAuditLambda(
            KmsConnectionService kmsConnectionService,
            ConfigurationService service,
            TXMAConfiguration txmaConfiguration) {
        super(kmsConnectionService, service);
        this.txmaConfiguration = Optional.of(txmaConfiguration);
    }

    public CounterFraudAuditLambda() {
        super();
        Optional<TXMAConfiguration> config;
        try {
            config = Optional.of(new TXMAConfiguration());
        } catch (Exception e) {
            config = Optional.empty();
            LOG.warn("Exception getting TXMA configuration ", e);
        }
        this.txmaConfiguration = config;
    }

    @Override
    void handleAuditEvent(AuditEvent auditEvent) {
        var eventData = new HashMap<String, String>();

        eventData.put("event-id", auditEvent.getEventId());
        eventData.put("request-id", auditEvent.getRequestId());
        eventData.put("session-id", auditEvent.getSessionId());
        eventData.put("client-id", auditEvent.getClientId());
        eventData.put("timestamp", auditEvent.getTimestamp());
        eventData.put("event-name", auditEvent.getEventName());
        eventData.put("persistent-session-id", auditEvent.getPersistentSessionId());

        User user = auditEvent.getUser();

        var hmacKey = this.service.getAuditHmacSecret();

        eventData.put("user.ip-address", user.getIpAddress());

        if (isPresent(user.getId())) {
            eventData.put("user.id", encodeHexString(hmacSha256(user.getId(), hmacKey)));
        }

        if (isPresent(user.getEmail())) {
            eventData.put("user.email", encodeHexString(hmacSha256(user.getEmail(), hmacKey)));
        }

        if (isPresent(user.getPhoneNumber())) {
            eventData.put(
                    "user.phone", encodeHexString(hmacSha256(user.getPhoneNumber(), hmacKey)));
        }

        txmaConfiguration.ifPresent(
                config -> {
                    var newHmacKey = config.getObfuscationHMACSecret();
                    newHmacKey.ifPresent(
                            key -> {
                                if (isPresent(user.getId())) {
                                    eventData.put(
                                            "user.id.txma",
                                            encodeHexString(hmacSha256(user.getId(), key)));
                                }

                                if (isPresent(user.getEmail())) {
                                    eventData.put(
                                            "user.email.txma",
                                            encodeHexString(hmacSha256(user.getEmail(), key)));
                                }

                                if (isPresent(user.getPhoneNumber())) {
                                    eventData.put(
                                            "user.phone.txma",
                                            encodeHexString(
                                                    hmacSha256(user.getPhoneNumber(), key)));
                                }
                            });
                });

        auditEvent
                .getExtensionsMap()
                .forEach((key, value) -> eventData.put("extensions." + key, value));

        LOG.info(new ObjectMessage(eventData));
    }

    private boolean isPresent(String field) {
        return !(field == null || field.isBlank());
    }
}
