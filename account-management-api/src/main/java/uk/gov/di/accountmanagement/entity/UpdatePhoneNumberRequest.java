package uk.gov.di.accountmanagement.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.authentication.shared.validation.Required;

public class UpdatePhoneNumberRequest {

    @Expose @Required private String email;

    @Expose
    @SerializedName("phoneNumber")
    @Required
    private String phoneNumber;

    @Expose @Required private String otp;

    public UpdatePhoneNumberRequest() {}

    public UpdatePhoneNumberRequest(String email, String phoneNumber, String otp) {
        this.email = email;
        this.phoneNumber = phoneNumber;
        this.otp = otp;
    }

    public String getEmail() {
        return email;
    }

    public String getPhoneNumber() {
        return phoneNumber;
    }

    public String getOtp() {
        return otp;
    }
}
