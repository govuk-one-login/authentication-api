package uk.gov.di.authentication.frontendapi.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.authentication.shared.entity.NotificationType;
import uk.gov.di.authentication.shared.validation.Required;

public class VerifyCodeRequest {

    public VerifyCodeRequest() {}

    public VerifyCodeRequest(NotificationType notificationType, String code) {
        this.notificationType = notificationType;
        this.code = code;
    }

    @SerializedName("notificationType")
    @Expose
    @Required
    private NotificationType notificationType;

    @SerializedName("code")
    @Expose
    @Required
    private String code;

    public NotificationType getNotificationType() {
        return notificationType;
    }

    public String getCode() {
        return code;
    }
}
