package uk.gov.di.authentication.auditevents.entity;

import com.google.gson.FieldNamingPolicy;
import com.google.gson.GsonBuilder;

public interface StructuredAuditEvent {
    String eventName();

    long timestamp();

    long eventTimestampMs();

    String clientId();

    String componentId();

    default String serialize() {
        var gson =
                new GsonBuilder()
                        .setFieldNamingPolicy(FieldNamingPolicy.LOWER_CASE_WITH_UNDERSCORES)
                        .create();
        return gson.toJson(this);
    }
}
