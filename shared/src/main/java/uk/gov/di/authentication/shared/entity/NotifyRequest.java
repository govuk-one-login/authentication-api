package uk.gov.di.authentication.shared.entity;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import jakarta.validation.constraints.NotNull;

public class NotifyRequest {

    @JsonProperty
    @Expose
    @SerializedName("notificationType")
    @NotNull
    private NotificationType notificationType;

    @JsonProperty @Expose @NotNull private String destination;

    @JsonProperty @Expose private String code;

    public NotifyRequest() {}

    @JsonCreator
    public NotifyRequest(
            @JsonProperty(required = true, value = "destination") String destination,
            @JsonProperty(required = true, value = "notificationType")
                    NotificationType notificationType,
            @JsonProperty(value = "code") String code) {
        this.destination = destination;
        this.notificationType = notificationType;
        this.code = code;
    }

    public NotifyRequest(String destination, NotificationType notificationType) {
        this(destination, notificationType, null);
    }

    public NotificationType getNotificationType() {
        return notificationType;
    }

    public String getDestination() {
        return destination;
    }

    public String getCode() {
        return code;
    }
}
