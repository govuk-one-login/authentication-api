package uk.gov.di.authentication.shared.entity;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public enum LevelOfConfidence {
    NONE("P0", true),
    LOW_LEVEL("P1", false),
    MEDIUM_LEVEL("P2", true),
    HIGH_LEVEL("P3", false),
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

    public static LevelOfConfidence retrieveLevelOfConfidence(String vrtSet) {
        return Arrays.stream(values())
                .filter(LevelOfConfidence::isSupported)
                .filter(tl -> vrtSet.equals(tl.getValue()))
                .findFirst()
                .orElseThrow(
                        () -> new IllegalArgumentException("Invalid LevelOfConfidence provided"));
    }

    public static List<String> getAllSupportedLevelOfConfidenceValues() {
        return Arrays.stream(LevelOfConfidence.values())
                .filter(LevelOfConfidence::isSupported)
                .map(LevelOfConfidence::getValue)
                .collect(Collectors.toList());
    }
}
