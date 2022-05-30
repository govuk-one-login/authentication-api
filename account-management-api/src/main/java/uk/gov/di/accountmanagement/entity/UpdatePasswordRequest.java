package uk.gov.di.accountmanagement.entity;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

public class UpdatePasswordRequest {

    @Expose private String email;

    @Expose
    @SerializedName("newPassword")
    private String newPassword;

    public UpdatePasswordRequest(
            @JsonProperty(required = true, value = "email") String email,
            @JsonProperty(required = true, value = "newPassword") String newPassword) {
        this.email = email;
        this.newPassword = newPassword;
    }

    public String getEmail() {
        return email;
    }

    public String getNewPassword() {
        return newPassword;
    }
}
