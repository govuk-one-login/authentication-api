package uk.gov.di.authentication.userpermissions.entity;

import uk.gov.di.authentication.shared.entity.AuthSessionItem;

public record UserPermissionContext(
        String internalSubjectId,
        String rpPairwiseId,
        String emailAddress,
        AuthSessionItem authSessionItem) {

    public static class Builder {
        private String internalSubjectId;
        private String rpPairwiseId;
        private String emailAddress;
        private AuthSessionItem authSessionItem;

        public Builder withInternalSubjectId(String internalSubjectId) {
            this.internalSubjectId = internalSubjectId;
            return this;
        }

        public Builder withRpPairwiseId(String rpPairwiseId) {
            this.rpPairwiseId = rpPairwiseId;
            return this;
        }

        public Builder withEmailAddress(String emailAddress) {
            this.emailAddress = emailAddress;
            return this;
        }

        public Builder withAuthSessionItem(AuthSessionItem authSessionItem) {
            this.authSessionItem = authSessionItem;
            return this;
        }

        public UserPermissionContext build() {
            return new UserPermissionContext(
                    internalSubjectId, rpPairwiseId, emailAddress, authSessionItem);
        }
    }

    public static Builder builder() {
        return new Builder();
    }
}
