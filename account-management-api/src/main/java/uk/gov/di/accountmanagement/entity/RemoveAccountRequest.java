package uk.gov.di.accountmanagement.entity;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.gson.annotations.Expose;

public class RemoveAccountRequest {
    @Expose private String email;

    public RemoveAccountRequest(@JsonProperty(required = true, value = "email") String email) {
        this.email = email;
    }

    public String getEmail() {
        return email;
    }
}
