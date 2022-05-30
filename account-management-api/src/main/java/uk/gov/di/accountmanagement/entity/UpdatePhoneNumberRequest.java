package uk.gov.di.accountmanagement.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import jakarta.validation.constraints.NotNull;

public class UpdatePhoneNumberRequest {

    @Expose @NotNull private String email;

    @Expose
    @SerializedName("phoneNumber")
    @NotNull
    private String phoneNumber;

    @Expose @NotNull private String otp;

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
