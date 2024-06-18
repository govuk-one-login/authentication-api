package uk.gov.di.orchestration.shared.entity;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static java.text.MessageFormat.format;

public enum CredentialTrustLevel {
    LOW_LEVEL(CredentialTrustLevelCode.CL),
    MEDIUM_LEVEL(CredentialTrustLevelCode.CL_CM);

    private static final Map<CredentialTrustLevelCode, CredentialTrustLevel> valueMap =
            new HashMap<>();

    static {
        for (var loc : values()) {
            for (var value : loc.allPermittedValues) {
                valueMap.put(value, loc);
            }
        }
    }

    private final CredentialTrustLevelCode defaultValue;
    private final Set<CredentialTrustLevelCode> allPermittedValues;

    CredentialTrustLevel(
            CredentialTrustLevelCode defaultValue, CredentialTrustLevelCode... aliasValues) {
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

    public static CredentialTrustLevel getDefault() {
        return MEDIUM_LEVEL;
    }

    public CredentialTrustLevelCode getDefaultCode() {
        return defaultValue;
    }

    public Set<CredentialTrustLevelCode> getAllCodes() {
        return allPermittedValues;
    }

    @Override
    public String toString() {
        return defaultValue.toString();
    }
}
