package uk.gov.di.authentication.shared.entity.mfa.request;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.JsonAdapter;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.authentication.shared.entity.PriorityIdentifier;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodNotificationIdentifier;
import uk.gov.di.authentication.shared.entity.mfa.MfaDetail;
import uk.gov.di.authentication.shared.validation.Required;

public record MfaMethodUpdateRequest(
        @Expose @Required @SerializedName("mfaMethod") MfaMethod mfaMethod,
        @Expose @SerializedName("notificationIdentifier")
                MFAMethodNotificationIdentifier notificationIdentifier) {

    public record MfaMethod(
            @Expose @Required @SerializedName("priorityIdentifier")
                    PriorityIdentifier priorityIdentifier,
            @Expose @SerializedName("method") @JsonAdapter(MfaDetailDeserializer.class)
                    MfaDetail method) {}

    public static MfaMethodUpdateRequest from(
            PriorityIdentifier priorityIdentifier, MfaDetail detail) {
        return from(priorityIdentifier, detail, null);
    }

    public static MfaMethodUpdateRequest from(
            PriorityIdentifier priorityIdentifier,
            MfaDetail detail,
            MFAMethodNotificationIdentifier notificationIdentifier) {
        return new MfaMethodUpdateRequest(
                new MfaMethod(priorityIdentifier, detail), notificationIdentifier);
    }
}
