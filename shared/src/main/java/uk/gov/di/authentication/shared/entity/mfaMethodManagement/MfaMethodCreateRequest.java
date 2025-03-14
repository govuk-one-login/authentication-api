package uk.gov.di.authentication.shared.entity.mfaMethodManagement;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.JsonAdapter;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.authentication.shared.entity.PriorityIdentifier;
import uk.gov.di.authentication.shared.serialization.MfaDetailDeserializer;

public record MfaMethodCreateRequest(@Expose @SerializedName("mfaMethod") MfaMethod mfaMethod) {
    public record MfaMethod(
            @Expose @SerializedName("priorityIdentifier") PriorityIdentifier priorityIdentifier,
            @Expose @SerializedName("method") @JsonAdapter(MfaDetailDeserializer.class)
                    MfaDetail method) {}
}
