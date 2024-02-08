package uk.gov.di.orchestration.shared.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

public record AccountInterventionState(
        @Expose boolean blocked,
        @Expose boolean suspended,
        @Expose @SerializedName("reproveIdentity") boolean reproveIdentity,
        @Expose @SerializedName("resetPassword") boolean resetPassword) {

    public AccountInterventionStatus getStatus() {
        if (blocked) return AccountInterventionStatus.BLOCKED;
        if (suspended) {
            if (!reproveIdentity && !resetPassword) {
                return AccountInterventionStatus.SUSPENDED_NO_ACTION;
            }
            if (reproveIdentity && !resetPassword) {
                return AccountInterventionStatus.SUSPENDED_REPROVE_ID;
            }
            if (!reproveIdentity && resetPassword) {
                return AccountInterventionStatus.SUSPENDED_RESET_PASSWORD;
            }
            if (reproveIdentity && resetPassword) {
                return AccountInterventionStatus.SUSPENDED_RESET_PASSWORD_REPROVE_ID;
            }
        }
        return AccountInterventionStatus.NO_INTERVENTION;
    }
}
