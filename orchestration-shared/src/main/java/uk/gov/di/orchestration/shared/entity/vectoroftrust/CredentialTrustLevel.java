package uk.gov.di.orchestration.shared.entity.vectoroftrust;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static java.text.MessageFormat.format;

/** Internal representation of credential authentication trust level. */
public enum CredentialTrustLevel {
    LOW_LEVEL(true, CredentialTrustLevelCode.CL, CredentialTrustLevelCode.C1),
    MEDIUM_LEVEL(true, CredentialTrustLevelCode.CL_CM, CredentialTrustLevelCode.C2),
    HIGH_LEVEL(false, CredentialTrustLevelCode.C3),
    VERY_HIGH_LEVEL(false, CredentialTrustLevelCode.C4);

    private static final Map<CredentialTrustLevelCode, CredentialTrustLevel> valueMap =
            new HashMap<>();

    static {
        for (var loc : values()) {
            for (var value : loc.allPermittedValues) {
                valueMap.put(value, loc);
            }
        }
    }

    private final boolean supported;
    private final CredentialTrustLevelCode defaultValue;
    private final Set<CredentialTrustLevelCode> allPermittedValues;

    CredentialTrustLevel(
            boolean supported,
            CredentialTrustLevelCode defaultValue,
            CredentialTrustLevelCode... aliasValues) {
        this.supported = supported;
        this.defaultValue = defaultValue;
        this.allPermittedValues =
                Stream.concat(Stream.of(defaultValue), Arrays.stream(aliasValues))
                        .collect(Collectors.toSet());
    }

    public static CredentialTrustLevel of(CredentialTrustLevelCode code) {
        if (valueMap.containsKey(code)) {
            return valueMap.get(code);
        }

        throw new IllegalArgumentException(
                format("Unknown \"Credential Trust Level\" \"{0}\".", code));
    }

    public static CredentialTrustLevel parse(String code) {
        return CredentialTrustLevel.of(CredentialTrustLevelCode.parse(code));
    }

    public CredentialTrustLevelCode getDefaultCode() {
        return defaultValue;
    }

    public boolean isSupported() {
        return supported;
    }

    @Override
    public String toString() {
        return defaultValue.toString();
    }
}
