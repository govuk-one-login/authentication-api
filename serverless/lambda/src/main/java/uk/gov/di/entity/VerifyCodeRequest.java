package uk.gov.di.entity;

import com.fasterxml.jackson.annotation.JsonProperty;

public class VerifyCodeRequest {

    @JsonProperty private NotificationType notificationType;

    @JsonProperty private String code;

    public VerifyCodeRequest(
            @JsonProperty(required = true, value = "notificationType") NotificationType notificationType,
            @JsonProperty(required = true, value = "code") String code) {
        this.notificationType = notificationType;
        this.code = code;
    }

    public NotificationType getNotificationType() {
        return notificationType;
    }

    public String getCode() {
        return code;
    }
}
