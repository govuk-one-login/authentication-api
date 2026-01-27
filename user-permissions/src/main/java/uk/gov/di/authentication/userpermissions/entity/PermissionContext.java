package uk.gov.di.authentication.userpermissions.entity;

import uk.gov.di.authentication.shared.entity.AuthSessionItem;

import java.util.List;
import java.util.Optional;

public record PermissionContext(
        List<String> internalSubjectIds,
        String rpPairwiseId,
        String emailAddress,
        AuthSessionItem authSessionItem,
        Optional<String> e164FormattedPhoneNumber) {

    public PermissionContext(
            String internalSubjectId,
            String rpPairwiseId,
            String emailAddress,
            AuthSessionItem authSessionItem,
            Optional<String> e164FormattedPhoneNumber) {
        this(
                internalSubjectId != null ? List.of(internalSubjectId) : List.of(),
                rpPairwiseId,
                emailAddress,
                authSessionItem,
                e164FormattedPhoneNumber);
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
        private Optional<String> e164FormattedPhoneNumber;

        public Builder from(PermissionContext permissionContext) {
            this.internalSubjectIds = permissionContext.internalSubjectIds;
            this.rpPairwiseId = permissionContext.rpPairwiseId;
            this.emailAddress = permissionContext.emailAddress;
            this.authSessionItem = permissionContext.authSessionItem;
            this.e164FormattedPhoneNumber = permissionContext.e164FormattedPhoneNumber;
            return this;
        }

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

        public Builder withE164FormattedPhoneNumber(String e164FormattedPhoneNumber) {
            this.e164FormattedPhoneNumber = Optional.ofNullable(e164FormattedPhoneNumber);
            return this;
        }

        public PermissionContext build() {
            return new PermissionContext(
                    internalSubjectIds,
                    rpPairwiseId,
                    emailAddress,
                    authSessionItem,
                    e164FormattedPhoneNumber);
        }
    }

    public static Builder builder() {
        return new Builder();
    }
}
