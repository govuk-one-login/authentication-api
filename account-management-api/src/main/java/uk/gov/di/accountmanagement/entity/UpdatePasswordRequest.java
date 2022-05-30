package uk.gov.di.accountmanagement.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import jakarta.validation.constraints.NotNull;

public class UpdatePasswordRequest {

    @Expose @NotNull private String email;

    @Expose
    @SerializedName("newPassword")
    @NotNull
    private String newPassword;

    public UpdatePasswordRequest() {}

    public UpdatePasswordRequest(String email, String newPassword) {
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
