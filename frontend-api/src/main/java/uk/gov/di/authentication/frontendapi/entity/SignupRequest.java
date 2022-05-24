package uk.gov.di.authentication.frontendapi.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import jakarta.validation.constraints.NotNull;
import uk.gov.di.authentication.shared.entity.BaseFrontendRequest;

public class SignupRequest extends BaseFrontendRequest {

    @SerializedName("password")
    @Expose
    @NotNull
    private String password;

    public SignupRequest() {}

    public SignupRequest(String email, String password) {
        this.email = email;
        this.password = password;
    }

    public String getPassword() {
        return password;
    }
}
