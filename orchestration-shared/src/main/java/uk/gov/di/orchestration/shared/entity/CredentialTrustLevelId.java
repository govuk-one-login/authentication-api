package uk.gov.di.orchestration.shared.entity;

import java.util.Optional;

/** IDs that can be used in an {@link CredentialTrustLevelCode}. */
public enum CredentialTrustLevelId {
    CL("Cl"),
    CM("Cm");

    private final String value;

    CredentialTrustLevelId(String value) {
        this.value = value;
    }

    public static Optional<CredentialTrustLevelId> tryParse(String id) {
        return VotComponentCode.tryParseId(CredentialTrustLevelId.class, id);
    }

    @Override
    public String toString() {
        return value;
    }
}
