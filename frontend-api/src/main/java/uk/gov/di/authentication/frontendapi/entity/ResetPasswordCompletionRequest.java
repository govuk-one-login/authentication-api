package uk.gov.di.authentication.frontendapi.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.authentication.shared.validation.Required;

public class ResetPasswordCompletionRequest {

    @SerializedName(value = "code")
    @Expose
    private String code;

    @SerializedName("password")
    @Expose
    @Required
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
