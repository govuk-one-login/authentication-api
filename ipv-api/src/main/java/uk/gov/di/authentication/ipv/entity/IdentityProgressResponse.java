package uk.gov.di.authentication.ipv.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.authentication.shared.validation.Required;

public class IdentityProgressResponse {

    @SerializedName("status")
    @Expose
    @Required
    private IdentityProgressStatus status;

    public IdentityProgressResponse() {}

    public IdentityProgressResponse(IdentityProgressStatus status) {
        this.status = status;
    }

    public IdentityProgressStatus getStatus() {
        return status;
    }
}
