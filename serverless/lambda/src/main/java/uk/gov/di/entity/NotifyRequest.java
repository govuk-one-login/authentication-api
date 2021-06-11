package uk.gov.di.entity;

import com.fasterxml.jackson.annotation.JsonProperty;

public class NotifyRequest {

    @JsonProperty
    private NotificationType notificationType;

    @JsonProperty
    private String destination;

    public NotifyRequest(@JsonProperty(required = true, value = "destination")  String destination,
                         @JsonProperty(required = true, value= "notificationType") NotificationType notificationType) {
        this.destination = destination;
        this.notificationType = notificationType;
    }

    public NotificationType getNotificationType() {
        return notificationType;
    }

    public String getDestination() {
        return destination;
    }
}
