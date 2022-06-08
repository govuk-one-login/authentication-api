package uk.gov.di.authentication.ipv.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.authentication.shared.validation.Required;

public class ProcessingIdentityResponse {

    @SerializedName("status")
    @Expose
    @Required
    private ProcessingIdentityStatus status;

    public ProcessingIdentityResponse() {}

    public ProcessingIdentityResponse(ProcessingIdentityStatus status) {
        this.status = status;
    }

    public ProcessingIdentityStatus getStatus() {
        return status;
    }
}
