package uk.gov.di.authentication.frontendapi.entity;

import com.fasterxml.jackson.annotation.JsonProperty;
import uk.gov.di.authentication.shared.entity.NotificationType;

public class VerifyCodeRequest {

    @JsonProperty private NotificationType notificationType;

    @JsonProperty private String code;

    public VerifyCodeRequest(
            @JsonProperty(required = true, value = "notificationType")
                    NotificationType notificationType,
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
