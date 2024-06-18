package uk.gov.di.orchestration.shared.entity;

import java.util.Optional;

/** IDs that can be used in an {@link LevelOfConfidenceCode} */
public enum LevelOfConfidenceId {
    P0("P0"),
    PCL200("PCL200"),
    PCL250("PCL250"),
    P2("P2");

    private final String value;

    LevelOfConfidenceId(String value) {
        this.value = value;
    }

    public static Optional<LevelOfConfidenceId> tryParse(String id) {
        return VotComponentCode.tryParseId(LevelOfConfidenceId.class, id);
    }

    @Override
    public String toString() {
        return value;
    }
}
