package uk.gov.di.orchestration.shared.entity;

public class AccountIntervention {

    private final AccountInterventionDetails details;
    private final AccountInterventionState state;
    private final AccountInterventionStatus status;
    private final boolean ignoreResetPassword;

    public AccountIntervention(AccountInterventionState state) {
        this.details = new AccountInterventionDetails(0L, 0L, 0L, "", 0L, 0L);
        this.state = state;
        this.ignoreResetPassword = false;
        this.status = deduceStatus();
    }

    public AccountIntervention(
            AccountInterventionDetails details,
            AccountInterventionState state,
            Long passwordResetTime) {
        this.details = details;
        this.state = state;
        this.ignoreResetPassword = details.appliedAt() < passwordResetTime;
        this.status = deduceStatus();
    }

    public AccountInterventionStatus getStatus() {
        if (status == null) {
            return deduceStatus();
        }
        return status;
    }

    public boolean getSuspended() {
        return state.suspended();
    }

    public boolean getBlocked() {
        return state.blocked();
    }

    public boolean getReproveIdentity() {
        return state.reproveIdentity();
    }

    public boolean getResetPassword() {
        return state.resetPassword();
    }

    private AccountInterventionStatus deduceStatus() {
        if (state.blocked()) {
            return AccountInterventionStatus.BLOCKED;
        }
        AccountInterventionStatus status = AccountInterventionStatus.NO_INTERVENTION;
        if (state.suspended()) {
            if (!state.reproveIdentity() && !state.resetPassword()) {
                status = AccountInterventionStatus.SUSPENDED_NO_ACTION;
            } else if (state.reproveIdentity() && !state.resetPassword()) {
                status = AccountInterventionStatus.SUSPENDED_REPROVE_ID;
            } else if (!state.reproveIdentity() && state.resetPassword()) {
                status = AccountInterventionStatus.SUSPENDED_RESET_PASSWORD;
            } else if (state.reproveIdentity() && state.resetPassword()) {
                status = AccountInterventionStatus.SUSPENDED_RESET_PASSWORD_REPROVE_ID;
            }
        }
        if (ignoreResetPassword) {
            if (status.equals(AccountInterventionStatus.SUSPENDED_RESET_PASSWORD)) {
                status = AccountInterventionStatus.NO_INTERVENTION;
            } else if (status.equals(
                    AccountInterventionStatus.SUSPENDED_RESET_PASSWORD_REPROVE_ID)) {
                status = AccountInterventionStatus.SUSPENDED_REPROVE_ID;
            }
        }
        return status;
    }
}
