package uk.gov.di.authentication.shared.entity.mfa.request;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.JsonAdapter;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.authentication.shared.entity.PriorityIdentifier;
import uk.gov.di.authentication.shared.entity.mfa.MfaDetail;
import uk.gov.di.authentication.shared.validation.Required;

public record MfaMethodCreateRequest(
        @Expose @Required @SerializedName("mfaMethod") MfaMethod mfaMethod) {
    public record MfaMethod(
            @Expose @Required @SerializedName("priorityIdentifier")
                    PriorityIdentifier priorityIdentifier,
            @Expose @Required @SerializedName("method") @JsonAdapter(MfaDetailDeserializer.class)
                    MfaDetail method) {}

    public static MfaMethodCreateRequest from(
            PriorityIdentifier priorityIdentifier, MfaDetail detail) {
        return new MfaMethodCreateRequest(new MfaMethod(priorityIdentifier, detail));
    }
}
