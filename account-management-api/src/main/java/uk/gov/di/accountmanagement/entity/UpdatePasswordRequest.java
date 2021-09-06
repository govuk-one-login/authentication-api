package uk.gov.di.accountmanagement.entity;

import com.fasterxml.jackson.annotation.JsonProperty;

public class UpdatePasswordRequest {

    private final String email;
    private final String newPassword;

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
