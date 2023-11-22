package uk.gov.di.authentication.interventions.api.stub.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

public class InterventionsApiStubResponse {

    public static class Interventions {
        @SerializedName("blocked")
        @Expose
        private Boolean blocked;

        @SerializedName("resetPassword")
        @Expose
        private Boolean resetPassword;

        @SerializedName("suspended")
        @Expose
        private Boolean suspended;

        @SerializedName("reproveIdentity")
        @Expose
        private Boolean reproveIdentity;

        public Interventions(AccountInterventionsStore accountInterventions) {
            this.blocked = accountInterventions.isBlocked();
            this.reproveIdentity = accountInterventions.isReproveIdentity();
            this.suspended = accountInterventions.isSuspended();
            this.resetPassword = accountInterventions.isResetPassword();
        }
    }

    public class State {

        @SerializedName("updatedAt")
        @Expose
        private Long updatedAt;

        @SerializedName("appliedAt")
        @Expose
        private Long appliedAt;

        @SerializedName("sentAt")
        @Expose
        private Long sentAt;

        @SerializedName("description")
        @Expose
        private String description;

        @SerializedName("reprovedIdentityAt")
        @Expose
        private Long reprovedIdentityAt;

        @SerializedName("resetPasswordAt")
        @Expose
        private Long resetPasswordAt;

        public State() {
            this.updatedAt = 1696969322935L;
            this.appliedAt = 1696869005821L;
            this.sentAt = 1696869003456L;
            this.description = "AIS_USER_PASSWORD_RESET_AND_IDENTITY_VERIFIED";
            this.reprovedIdentityAt = 1696969322935L;
            this.resetPasswordAt = 1696875903456L;
        }
    }

    @Expose
    @SerializedName("intervention")
    private Interventions interventions;

    @Expose
    @SerializedName("state")
    private State state;

    public InterventionsApiStubResponse(AccountInterventionsStore accountInterventions) {
        this.state = new State();
        this.interventions = new Interventions(accountInterventions);
    }
}
