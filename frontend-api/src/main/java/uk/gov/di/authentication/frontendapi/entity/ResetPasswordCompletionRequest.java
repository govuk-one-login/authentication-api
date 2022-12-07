package uk.gov.di.authentication.frontendapi.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.authentication.shared.validation.Required;

public class ResetPasswordCompletionRequest {

    @SerializedName("password")
    @Expose
    @Required
    private String password;

    public ResetPasswordCompletionRequest() {}

    public ResetPasswordCompletionRequest(String password) {
        this.password = password;
    }

    public String getPassword() {
        return password;
    }
}
