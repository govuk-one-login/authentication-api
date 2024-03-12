package uk.gov.di.orchestration.shared.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

public class AccountInterventionStatus {
    @Expose private final boolean blocked;
    @Expose private final boolean suspended;

    @Expose
    @SerializedName("reproveIdentity")
    private final boolean reproveIdentity;

    @Expose
    @SerializedName("resetPassword")
    private final boolean resetPassword;

    private AccountInterventionInfo info;

    public AccountInterventionStatus(
            boolean blocked, boolean suspended, boolean reproveIdentity, boolean resetPassword) {
        this.blocked = blocked;
        this.suspended = suspended;
        this.reproveIdentity = reproveIdentity;
        this.resetPassword = resetPassword;
    }

    public AccountInterventionInfo getInfo() {
        return this.info;
    }

    public void setInfo(AccountInterventionInfo info) {
        this.info = info;
    }

    public boolean blocked() {
        return blocked;
    }

    public boolean suspended() {
        return suspended;
    }

    public boolean reproveIdentity() {
        return reproveIdentity;
    }

    public boolean resetPassword() {
        return resetPassword;
    }
}
