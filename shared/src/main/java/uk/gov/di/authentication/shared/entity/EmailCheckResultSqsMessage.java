package uk.gov.di.authentication.shared.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.authentication.shared.validation.Required;

public class EmailCheckResultSqsMessage {
    @Expose
    @SerializedName("Email")
    @Required
    private String email;

    @Expose
    @SerializedName("Status")
    @Required
    private EmailCheckResultStatus emailCheckResultStatus;

    @Expose
    @SerializedName("TimeToExist")
    @Required
    private long timeToExist;

    @Expose
    @SerializedName("ReferenceNumber")
    @Required
    private String referenceNumber;

    public EmailCheckResultSqsMessage(
            String email,
            EmailCheckResultStatus emailCheckResultStatus,
            long timeToExist,
            String referenceNumber) {
        this.email = email;
        this.emailCheckResultStatus = emailCheckResultStatus;
        this.timeToExist = timeToExist;
        this.referenceNumber = referenceNumber;
    }

    public String getEmail() {
        return email;
    }

    public EmailCheckResultStatus getEmailCheckResultStatus() {
        return emailCheckResultStatus;
    }

    public long getTimeToExist() {
        return timeToExist;
    }

    public String getReferenceNumber() {
        return referenceNumber;
    }
}
