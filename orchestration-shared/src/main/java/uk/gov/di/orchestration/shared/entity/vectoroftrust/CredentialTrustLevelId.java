package uk.gov.di.orchestration.shared.entity.vectoroftrust;

import java.util.Optional;

/** IDs that can be used in an {@link CredentialTrustLevelCode}. */
public enum CredentialTrustLevelId {
    CL("Cl"),
    C1("C1"),
    CM("Cm"),
    C2("C2"),
    C3("C3"),
    C4("C4");

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
