package uk.gov.di.authentication.frontendapi.entity;

import com.fasterxml.jackson.annotation.JsonProperty;

public class ResetPasswordWithCodeRequest {

    private String code;
    private String password;

    public ResetPasswordWithCodeRequest(
            @JsonProperty(required = true, value = "code") String code,
            @JsonProperty(required = true, value = "password") String password) {
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
