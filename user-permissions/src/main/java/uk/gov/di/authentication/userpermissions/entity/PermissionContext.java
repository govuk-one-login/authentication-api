package uk.gov.di.authentication.userpermissions.entity;

import uk.gov.di.authentication.shared.entity.AuthSessionItem;

import java.util.List;

public record PermissionContext(
        List<String> internalSubjectIds,
        String rpPairwiseId,
        String emailAddress,
        AuthSessionItem authSessionItem) {

    public PermissionContext(
            String internalSubjectId,
            String rpPairwiseId,
            String emailAddress,
            AuthSessionItem authSessionItem) {
        this(
                internalSubjectId != null ? List.of(internalSubjectId) : List.of(),
                rpPairwiseId,
                emailAddress,
                authSessionItem);
    }

    public String internalSubjectId() {
        if (internalSubjectIds == null || internalSubjectIds.isEmpty()) {
            return null;
        }
        if (internalSubjectIds.size() > 1) {
            throw new IllegalStateException(
                    "Cannot get single internalSubjectId when multiple IDs exist");
        }
        return internalSubjectIds.get(0);
    }

    public static class Builder {
        private List<String> internalSubjectIds;
        private String rpPairwiseId;
        private String emailAddress;
        private AuthSessionItem authSessionItem;

        public Builder withInternalSubjectId(String internalSubjectId) {
            return withInternalSubjectIds(
                    internalSubjectId != null ? List.of(internalSubjectId) : List.of());
        }

        public Builder withInternalSubjectIds(List<String> internalSubjectIds) {
            this.internalSubjectIds = internalSubjectIds;
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

        public PermissionContext build() {
            return new PermissionContext(
                    internalSubjectIds, rpPairwiseId, emailAddress, authSessionItem);
        }
    }

    public static Builder builder() {
        return new Builder();
    }
}
