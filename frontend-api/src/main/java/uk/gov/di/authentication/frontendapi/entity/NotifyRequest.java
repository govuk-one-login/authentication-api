package uk.gov.di.authentication.frontendapi.entity;

import com.fasterxml.jackson.annotation.JsonProperty;

public class NotifyRequest {

    @JsonProperty private NotificationType notificationType;

    @JsonProperty private String destination;

    @JsonProperty private String code;

    public NotifyRequest(
            @JsonProperty(required = true, value = "destination") String destination,
            @JsonProperty(required = true, value = "notificationType")
                    NotificationType notificationType,
            @JsonProperty(value = "code") String code) {
        this.destination = destination;
        this.notificationType = notificationType;
        this.code = code;
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
