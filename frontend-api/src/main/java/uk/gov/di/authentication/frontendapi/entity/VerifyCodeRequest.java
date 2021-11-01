package uk.gov.di.authentication.frontendapi.entity;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotNull;
import uk.gov.di.authentication.shared.entity.NotificationType;

public class VerifyCodeRequest {

    @JsonProperty(required = true, value = "notificationType")
    @NotNull
    private NotificationType notificationType;

    @JsonProperty(required = true, value = "code")
    @NotNull
    private String code;

    public NotificationType getNotificationType() {
        return notificationType;
    }

    public String getCode() {
        return code;
    }
}
