package uk.gov.di.authentication.ipv.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.orchestration.shared.validation.Required;

public class ProcessingIdentityInterventionResponse {

    @SerializedName("status")
    @Expose
    @Required
    private ProcessingIdentityStatus status;

    @SerializedName("redirectUrl")
    @Expose
    @Required
    private String redirectUrl;

    public ProcessingIdentityInterventionResponse() {}

    public ProcessingIdentityInterventionResponse(
            ProcessingIdentityStatus status, String redirectUrl) {
        this.status = status;
        this.redirectUrl = redirectUrl;
    }
}
