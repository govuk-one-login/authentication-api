package uk.gov.di.orchestration.shared.entity;

import java.util.Arrays;
import java.util.List;

public enum LevelOfConfidence {
    NONE("P0", true),
    HMRC200("PCL200", true),
    HMRC250("PCL250", true),
    LOW_LEVEL("P1", true),
    MEDIUM_LEVEL("P2", true),
    HIGH_LEVEL("P3", true),
    VERY_HIGH_LEVEL("P4", false);

    private String value;
    private boolean supported;

    LevelOfConfidence(String value, boolean supported) {
        this.value = value;
        this.supported = supported;
    }

    public String getValue() {
        return value;
    }

    public boolean isSupported() {
        return supported;
    }

    public static LevelOfConfidence retrieveLevelOfConfidence(String vtrSet) {
        return Arrays.stream(values())
                .filter(LevelOfConfidence::isSupported)
                .filter(tl -> vtrSet.equals(tl.getValue()))
                .findFirst()
                .orElseThrow(
                        () -> new IllegalArgumentException("Invalid LevelOfConfidence provided"));
    }

    public static List<String> getAllSupportedLevelOfConfidenceValues() {
        return Arrays.stream(LevelOfConfidence.values())
                .filter(LevelOfConfidence::isSupported)
                .map(LevelOfConfidence::getValue)
                .toList();
    }

    public static LevelOfConfidence getDefault() {
        return MEDIUM_LEVEL;
    }

    public static List<String> getDefaultLevelOfConfidenceValues() {
        List<LevelOfConfidence> defaults =
                List.of(
                        LevelOfConfidence.NONE,
                        LevelOfConfidence.LOW_LEVEL,
                        LevelOfConfidence.MEDIUM_LEVEL,
                        LevelOfConfidence.HIGH_LEVEL,
                        LevelOfConfidence.VERY_HIGH_LEVEL);
        return defaults.stream()
                .filter(LevelOfConfidence::isSupported)
                .map(LevelOfConfidence::getValue)
                .toList();
    }
}
