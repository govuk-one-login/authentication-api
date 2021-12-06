package uk.gov.di.authentication.shared.entity;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public enum LevelOfConfidence {
    LOW_LEVEL("Pl"),
    MEDIUM_LEVEL("Pm"),
    HIGH_LEVEL("Ph"),
    VERY_HIGH_LEVEL("Pv");

    private String value;

    LevelOfConfidence(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }

    public static LevelOfConfidence retrieveLevelOfConfidence(String vrtSet) {

        return Arrays.stream(values())
                .filter(tl -> vrtSet.equals(tl.getValue()))
                .findFirst()
                .orElseThrow(
                        () -> new IllegalArgumentException("Invalid LevelOfConfidence provided"));
    }

    public static List<String> getAllLevelOfConfidenceValues() {
        return Arrays.stream(LevelOfConfidence.values())
                .map(LevelOfConfidence::getValue)
                .collect(Collectors.toList());
    }
}
