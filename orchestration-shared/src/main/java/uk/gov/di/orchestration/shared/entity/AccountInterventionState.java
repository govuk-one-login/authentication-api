package uk.gov.di.orchestration.shared.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

public class AccountInterventionState {

    @Expose private final boolean blocked;

    @Expose private final boolean suspended;

    @Expose
    @SerializedName("reproveIdentity")
    private final boolean reproveIdentity;

    @Expose
    @SerializedName("resetPassword")
    private final boolean resetPassword;

    private AccountInterventionStatus status;

    public AccountInterventionState(
            boolean blocked, boolean suspended, boolean reproveIdentity, boolean resetPassword) {
        this.blocked = blocked;
        this.suspended = suspended;
        this.reproveIdentity = reproveIdentity;
        this.resetPassword = resetPassword;
        this.status = calculateStatus();
    }

    public boolean blocked() {
        return blocked;
    }

    public boolean suspended() {
        return suspended;
    }

    public boolean resetPassword() {
        return resetPassword;
    }

    public boolean reproveIdentity() {
        return reproveIdentity;
    }

    public AccountInterventionStatus getStatus() {
        if (status == null) {
            this.status = calculateStatus();
        }
        return status;
    }

    private AccountInterventionStatus calculateStatus() {
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
