package uk.gov.di.authentication.frontendapi.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.NotificationType;
import uk.gov.di.authentication.shared.validation.Required;

public class VerifyCodeRequest {

    public VerifyCodeRequest() {}

    public VerifyCodeRequest(NotificationType notificationType, String code) {
        this.notificationType = notificationType;
        this.code = code;
    }

    public VerifyCodeRequest(
            NotificationType notificationType, String code, JourneyType journeyType) {
        this.notificationType = notificationType;
        this.code = code;
        this.journeyType = journeyType;
    }

    @SerializedName("notificationType")
    @Expose
    @Required
    private NotificationType notificationType;

    @SerializedName("code")
    @Expose
    @Required
    private String code;

    @SerializedName("journeyType")
    @Expose
    protected JourneyType journeyType;

    public NotificationType getNotificationType() {
        return notificationType;
    }

    public String getCode() {
        return code;
    }

    public JourneyType getJourneyType() {
        return journeyType;
    }
}
