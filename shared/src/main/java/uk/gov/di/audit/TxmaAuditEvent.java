package uk.gov.di.audit;

import com.google.gson.annotations.Expose;
import uk.gov.di.authentication.shared.domain.AuditableEvent;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.services.SerializationService;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Supplier;

public class TxmaAuditEvent {

    @Expose private final long timestamp;

    @Expose private final long eventTimestampMs;

    @Expose private final String eventName;

    @Expose private String clientId;

    @Expose private String componentId;

    @Expose private TxmaAuditUser user;

    @Expose private Map<String, Object> platform;
    @Expose private Map<String, Object> restricted;
    @Expose private Map<String, Object> extensions;

    public TxmaAuditEvent(String eventName, long timestamp, long eventTimestampMs) {
        this.eventName = eventName;
        this.timestamp = timestamp;
        this.eventTimestampMs = eventTimestampMs;
    }

    public static TxmaAuditEvent auditEventWithTime(
            AuditableEvent eventName, Supplier<Date> dateSupplier) {
        return new TxmaAuditEvent(
                eventName.toString(),
                dateSupplier.get().toInstant().getEpochSecond(),
                dateSupplier.get().toInstant().toEpochMilli());
    }

    public static TxmaAuditEvent auditEvent(AuditableEvent event) {
        return auditEventWithTime(event, NowHelper::now);
    }

    public String serialize() {
        return SerializationService.getInstance().writeValueAsString(this);
    }

    public TxmaAuditEvent withComponentId(String componentId) {
        this.componentId = componentId;
        return this;
    }

    public TxmaAuditEvent withClientId(String clientId) {
        this.clientId = clientId;
        return this;
    }

    public TxmaAuditEvent withUser(TxmaAuditUser user) {
        this.user = user;
        return this;
    }

    public TxmaAuditEvent addPlatform(String key, Object value) {
        if (this.platform == null) {
            this.platform = new HashMap<>();
        }

        this.platform.put(key, value);

        return this;
    }

    public TxmaAuditEvent addRestricted(String key, Object value) {
        if (this.restricted == null) {
            this.restricted = new HashMap<>();
        }

        this.restricted.put(key, value);

        return this;
    }

    public TxmaAuditEvent addExtension(String key, Object value) {
        if (this.extensions == null) {
            this.extensions = new HashMap<>();
        }

        this.extensions.put(key, value);

        return this;
    }
}
