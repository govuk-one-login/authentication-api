package uk.gov.di.orchestration.shared.entity;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static java.text.MessageFormat.format;

public enum LevelOfConfidence {
    NONE(LevelOfConfidenceCode.P0, LevelOfConfidenceCode.EMPTY),
    HMRC200(LevelOfConfidenceCode.PCL200),
    HMRC250(LevelOfConfidenceCode.PCL250),
    MEDIUM_LEVEL(LevelOfConfidenceCode.P2);

    private static final Map<LevelOfConfidenceCode, LevelOfConfidence> valueMap = new HashMap<>();

    static {
        for (var loc : values()) {
            for (var value : loc.allPermittedValues) {
                valueMap.put(value, loc);
            }
        }
    }

    private final LevelOfConfidenceCode defaultValue;
    private final Set<LevelOfConfidenceCode> allPermittedValues;

    LevelOfConfidence(LevelOfConfidenceCode defaultValue, LevelOfConfidenceCode... aliasValues) {
        this.defaultValue = defaultValue;
        this.allPermittedValues =
                Stream.concat(Stream.of(defaultValue), Arrays.stream(aliasValues))
                        .collect(Collectors.toSet());
    }

    public static LevelOfConfidence of(LevelOfConfidenceCode code) {
        if (valueMap.containsKey(code)) {
            return valueMap.get(code);
        }

        throw new IllegalArgumentException(
                format("Unknown \"Level of Confidence\" \"{0}\".", code));
    }

    public static LevelOfConfidence getDefault() {
        return NONE;
    }

    public LevelOfConfidenceCode getDefaultCode() {
        return defaultValue;
    }

    public Set<LevelOfConfidenceCode> getAllCodes() {
        return allPermittedValues;
    }

    @Override
    public String toString() {
        return defaultValue.toString();
    }
}
