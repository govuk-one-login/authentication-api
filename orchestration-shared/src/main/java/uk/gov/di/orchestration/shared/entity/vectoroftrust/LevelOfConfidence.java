package uk.gov.di.orchestration.shared.entity.vectoroftrust;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static java.text.MessageFormat.format;

/** Internal representation of identity verification trust level. */
public enum LevelOfConfidence {
    NONE(true, Kind.NONE, LevelOfConfidenceCode.P0, LevelOfConfidenceCode.EMPTY),
    HMRC200(true, Kind.HMRC, LevelOfConfidenceCode.PCL200),
    HMRC250(true, Kind.HMRC, LevelOfConfidenceCode.PCL250),
    LOW_LEVEL(false, Kind.STANDARD, LevelOfConfidenceCode.P1),
    MEDIUM_LEVEL(true, Kind.STANDARD, LevelOfConfidenceCode.P2),
    HIGH_LEVEL(false, Kind.STANDARD, LevelOfConfidenceCode.P3),
    VERY_HIGH_LEVEL(false, Kind.STANDARD, LevelOfConfidenceCode.P4);

    private static final Map<LevelOfConfidenceCode, LevelOfConfidence> valueMap = new HashMap<>();

    static {
        for (var loc : values()) {
            for (var value : loc.allPermittedValues) {
                valueMap.put(value, loc);
            }
        }
    }

    private final boolean supported;
    private final Kind kind;
    private final LevelOfConfidenceCode defaultValue;
    private final Set<LevelOfConfidenceCode> allPermittedValues;

    LevelOfConfidence(
            boolean supported,
            Kind kind,
            LevelOfConfidenceCode defaultValue,
            LevelOfConfidenceCode... aliasValues) {
        this.supported = supported;
        this.defaultValue = defaultValue;
        this.kind = kind;
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

    public static LevelOfConfidence parse(String code) {
        return LevelOfConfidence.of(LevelOfConfidenceCode.parse(code));
    }

    public LevelOfConfidenceCode getDefaultCode() {
        return defaultValue;
    }

    public boolean isSupported() {
        return supported;
    }

    public Kind getKind() {
        return kind;
    }

    public enum Kind {
        NONE,
        STANDARD,
        HMRC,
    }

    @Override
    public String toString() {
        return defaultValue.toString();
    }
}
