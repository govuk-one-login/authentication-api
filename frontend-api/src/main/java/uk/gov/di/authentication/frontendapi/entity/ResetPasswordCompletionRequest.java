package uk.gov.di.authentication.frontendapi.entity;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotNull;

public class ResetPasswordCompletionRequest {
    @JsonProperty(value = "code")
    private String code;

    @JsonProperty(required = true, value = "password")
    @NotNull
    private String password;

    public ResetPasswordCompletionRequest() {}

    public ResetPasswordCompletionRequest(String code, String password) {
        this.code = code;
        this.password = password;
    }

    public String getCode() {
        return code;
    }

    public String getPassword() {
        return password;
    }
}
