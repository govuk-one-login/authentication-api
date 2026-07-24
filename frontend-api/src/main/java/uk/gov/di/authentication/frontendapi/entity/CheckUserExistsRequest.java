package uk.gov.di.authentication.frontendapi.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.authentication.shared.entity.BaseFrontendRequest;

public class CheckUserExistsRequest extends BaseFrontendRequest {

    @Expose
    @SerializedName("supportPasskeyUsage")
    private boolean supportPasskeyUsage;

    public CheckUserExistsRequest() {}

    public CheckUserExistsRequest(String email) {
        this.email = email;
    }

    public CheckUserExistsRequest(String email, boolean supportPasskeyUsage) {
        this.email = email;
        this.supportPasskeyUsage = supportPasskeyUsage;
    }

    public boolean isSupportPasskeyUsage() {
        return supportPasskeyUsage;
    }

    @Override
    public String toString() {
        return "CheckUserExistsRequest{"
                + "email='"
                + email
                + '\''
                + ", supportPasskeyUsage="
                + supportPasskeyUsage
                + '}';
    }
}
