package uk.gov.di.accountmanagement.entity;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

public class UpdatePhoneNumberRequest {

    @Expose private String email;

    @Expose
    @SerializedName("phoneNumber")
    private String phoneNumber;

    @Expose private String otp;

    public UpdatePhoneNumberRequest(
            @JsonProperty(required = true, value = "email") String email,
            @JsonProperty(required = true, value = "phoneNumber") String phoneNumber,
            @JsonProperty(required = true, value = "otp") String otp) {
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
