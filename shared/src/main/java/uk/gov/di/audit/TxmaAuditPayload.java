package uk.gov.di.audit;

import com.google.gson.annotations.Expose;
import uk.gov.di.authentication.shared.domain.AuditableEvent;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.services.SerializationService;

import java.util.Date;
import java.util.function.Supplier;

public class TxmaAuditPayload {

    @Expose private final long timestamp;

    @Expose private final String eventName;

    public TxmaAuditPayload(String eventName, long timestamp) {
        this.eventName = eventName;
        this.timestamp = timestamp;
    }

    protected static TxmaAuditPayload auditEventWithTime(
            AuditableEvent eventName, Supplier<Date> dateSupplier) {
        return new TxmaAuditPayload("AUTH_" + eventName.toString(), dateSupplier.get().getTime());
    }

    public static TxmaAuditPayload auditEvent(AuditableEvent event) {
        return auditEventWithTime(event, NowHelper::now);
    }

    public String serialize() {
        return SerializationService.getInstance().writeValueAsString(this);
    }
}
