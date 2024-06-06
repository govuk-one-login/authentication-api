package uk.gov.di.orchestration.shared.entity;

import com.google.gson.annotations.Expose;

import java.util.Arrays;
import java.util.Objects;
import java.util.stream.Collectors;

import static uk.gov.di.orchestration.shared.entity.LevelOfConfidence.NONE;

public class VectorOfTrust {

    public static final VectorOfTrust DEFAULT_VECTOR_OF_TRUST =
            new VectorOfTrust(CredentialTrustLevel.getDefault(), LevelOfConfidence.getDefault());

    @Expose private CredentialTrustLevel credentialTrustLevel;

    @Expose private LevelOfConfidence levelOfConfidence;

    public VectorOfTrust(CredentialTrustLevel credentialTrustLevel) {
        this(credentialTrustLevel, NONE);
    }

    public VectorOfTrust(
            CredentialTrustLevel credentialTrustLevel, LevelOfConfidence levelOfConfidence) {
        this.credentialTrustLevel = credentialTrustLevel;
        this.levelOfConfidence = levelOfConfidence;
    }

    public CredentialTrustLevel getCredentialTrustLevel() {
        return credentialTrustLevel;
    }

    public LevelOfConfidence getLevelOfConfidence() {
        return levelOfConfidence;
    }

    public static VectorOfTrust parse(String vectorOfTrust) {
        var splitVtr = vectorOfTrust.split("\\.");

        var levelOfConfidence =
                Arrays.stream(splitVtr)
                        .filter(a -> a.startsWith("P"))
                        .map(LevelOfConfidence::retrieveLevelOfConfidence)
                        .collect(
                                Collectors.collectingAndThen(
                                        Collectors.toList(),
                                        list -> {
                                            if (list.size() > 1) {
                                                throw new IllegalArgumentException(
                                                        "VTR must contain either 0 or 1 identity proofing components");
                                            }
                                            return list;
                                        }))
                        .stream()
                        .findFirst();

        var credentialTrustLevel =
                CredentialTrustLevel.retrieveCredentialTrustLevel(
                        Arrays.stream(splitVtr)
                                .filter(a -> a.startsWith("C"))
                                .sorted()
                                .collect(Collectors.joining(".")));

        return levelOfConfidence
                .map(ofConfidence -> new VectorOfTrust(credentialTrustLevel, ofConfidence))
                .orElseGet(() -> new VectorOfTrust(credentialTrustLevel));
    }

    @Override
    public String toString() {
        return "VectorOfTrust{"
                + "credentialTrustLevel="
                + credentialTrustLevel
                + ", levelOfConfidence="
                + levelOfConfidence
                + '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        VectorOfTrust that = (VectorOfTrust) o;
        return credentialTrustLevel == that.credentialTrustLevel
                && levelOfConfidence == that.levelOfConfidence;
    }

    @Override
    public int hashCode() {
        return Objects.hash(credentialTrustLevel, levelOfConfidence);
    }
}
