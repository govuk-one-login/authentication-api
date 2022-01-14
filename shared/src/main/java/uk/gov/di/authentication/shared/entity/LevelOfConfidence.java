package uk.gov.di.authentication.shared.entity;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public enum LevelOfConfidence {
    LOW_LEVEL("Pl", false),
    MEDIUM_LEVEL("Pm", true),
    HIGH_LEVEL("Ph", false),
    VERY_HIGH_LEVEL("Pv", false);

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
