package uk.gov.di.accountmanagement.entity;

import com.google.gson.annotations.Expose;
import jakarta.validation.constraints.NotNull;

public class RemoveAccountRequest {
    @Expose @NotNull private String email;

    public RemoveAccountRequest() {}

    public RemoveAccountRequest(String email) {
        this.email = email;
    }

    public String getEmail() {
        return email;
    }
}
