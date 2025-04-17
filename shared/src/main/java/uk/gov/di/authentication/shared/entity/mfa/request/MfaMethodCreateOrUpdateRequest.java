package uk.gov.di.authentication.shared.entity.mfa.request;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.JsonAdapter;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.authentication.shared.entity.PriorityIdentifier;
import uk.gov.di.authentication.shared.entity.mfa.MfaDetail;

public record MfaMethodCreateOrUpdateRequest(
        @Expose @SerializedName("mfaMethod") MfaMethod mfaMethod) {
    public record MfaMethod(
            @Expose @SerializedName("priorityIdentifier") PriorityIdentifier priorityIdentifier,
            @Expose @SerializedName("method") @JsonAdapter(MfaDetailDeserializer.class)
                    MfaDetail method) {}

    public static MfaMethodCreateOrUpdateRequest from(
            PriorityIdentifier priorityIdentifier, MfaDetail detail) {
        return new MfaMethodCreateOrUpdateRequest(new MfaMethod(priorityIdentifier, detail));
    }
}
