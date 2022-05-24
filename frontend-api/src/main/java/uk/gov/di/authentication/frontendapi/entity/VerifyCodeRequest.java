package uk.gov.di.authentication.frontendapi.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import jakarta.validation.constraints.NotNull;
import uk.gov.di.authentication.shared.entity.NotificationType;

public class VerifyCodeRequest {

    public VerifyCodeRequest() {}

    public VerifyCodeRequest(NotificationType notificationType, String code) {
        this.notificationType = notificationType;
        this.code = code;
    }

    @SerializedName("notificationType")
    @Expose
    @NotNull
    private NotificationType notificationType;

    @SerializedName("code")
    @Expose
    @NotNull
    private String code;

    public NotificationType getNotificationType() {
        return notificationType;
    }

    public String getCode() {
        return code;
    }
}
