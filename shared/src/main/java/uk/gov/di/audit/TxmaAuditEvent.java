package uk.gov.di.audit;

import com.google.gson.annotations.Expose;
import uk.gov.di.authentication.shared.domain.AuditableEvent;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.services.SerializationService;

import java.util.Date;
import java.util.function.Supplier;

public class TxmaAuditEvent {

    @Expose private final long timestamp;

    @Expose private final String eventName;

    @Expose private String clientId;

    @Expose private String componentName;

    @Expose private TxmaAuditUser user;

    public TxmaAuditEvent(String eventName, long timestamp) {
        this.eventName = eventName;
        this.timestamp = timestamp;
    }

    protected static TxmaAuditEvent auditEventWithTime(
            AuditableEvent eventName, Supplier<Date> dateSupplier) {
        return new TxmaAuditEvent("AUTH_" + eventName.toString(), dateSupplier.get().getTime());
    }

    public static TxmaAuditEvent auditEvent(AuditableEvent event) {
        return auditEventWithTime(event, NowHelper::now);
    }

    public String serialize() {
        return SerializationService.getInstance().writeValueAsString(this);
    }

    public TxmaAuditEvent withComponentName(String componentName) {
        this.componentName = componentName;
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
}
