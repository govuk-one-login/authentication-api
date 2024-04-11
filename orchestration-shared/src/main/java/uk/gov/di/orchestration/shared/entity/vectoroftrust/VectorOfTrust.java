package uk.gov.di.orchestration.shared.entity.vectoroftrust;

import com.nimbusds.jose.shaded.gson.annotations.Expose;
import org.jetbrains.annotations.NotNull;

import java.util.Comparator;
import java.util.EnumSet;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static java.text.MessageFormat.format;

/**
 * A Vector of Trust represents a combined credential authentication and identity verification trust
 * level.
 */
public class VectorOfTrust implements Comparable<VectorOfTrust> {

    @Expose private CredentialTrustLevelCode credentialTrustLevelCode;
    @Expose private final CredentialTrustLevel credentialTrustLevel;

    @Expose private LevelOfConfidenceCode levelOfConfidenceCode;
    @Expose private final LevelOfConfidence levelOfConfidence;

    public static final VectorOfTrust DEFAULT = VectorOfTrust.of(CredentialTrustLevel.MEDIUM_LEVEL);

    private VectorOfTrust(CredentialTrustLevelCode ctlCode, LevelOfConfidenceCode locCode) {
        this.credentialTrustLevelCode = ctlCode;
        this.credentialTrustLevel = CredentialTrustLevel.of(ctlCode);
        this.levelOfConfidenceCode = locCode;
        this.levelOfConfidence = LevelOfConfidence.of(locCode);
    }

    public static VectorOfTrust of(CredentialTrustLevel ctl) {
        return VectorOfTrust.of(ctl.getDefaultCode());
    }

    public static VectorOfTrust of(CredentialTrustLevel ctl, LevelOfConfidence loc) {
        return VectorOfTrust.of(ctl.getDefaultCode(), loc.getDefaultCode());
    }

    public static VectorOfTrust of(CredentialTrustLevelCode ctlCode) {
        return new VectorOfTrust(ctlCode, LevelOfConfidenceCode.EMPTY);
    }

    public static VectorOfTrust of(
            CredentialTrustLevelCode ctlCode, LevelOfConfidenceCode locCode) {
        return new VectorOfTrust(ctlCode, locCode);
    }

    public static VectorOfTrust parse(String vectorOfTrust) {
        EnumSet<CredentialTrustLevelId> ctlComponentIds =
                EnumSet.noneOf(CredentialTrustLevelId.class);
        EnumSet<LevelOfConfidenceId> locComponentIds = EnumSet.noneOf(LevelOfConfidenceId.class);

        if (!vectorOfTrust.isEmpty()) {
            for (var componentId : vectorOfTrust.split("\\.", -1)) {
                Optional<CredentialTrustLevelId> authId =
                        CredentialTrustLevelId.tryParse(componentId);
                if (authId.isPresent()) {
                    ctlComponentIds.add(authId.get());
                    continue;
                }

                Optional<LevelOfConfidenceId> identId = LevelOfConfidenceId.tryParse(componentId);
                if (identId.isPresent()) {
                    locComponentIds.add(identId.get());
                    continue;
                }

                throw new IllegalArgumentException(
                        format("Unknown ID \"{0}\" in VoT \"{1}\".", componentId, vectorOfTrust));
            }
        }

        return new VectorOfTrust(
                new CredentialTrustLevelCode(ctlComponentIds),
                new LevelOfConfidenceCode(locComponentIds));
    }

    public CredentialTrustLevelCode getCredentialTrustLevelCode() {
        // ATO-98: This should only ever be null if a session was in progress during release.
        if (credentialTrustLevelCode == null) {
            credentialTrustLevelCode = credentialTrustLevel.getDefaultCode();
        }
        return credentialTrustLevelCode;
    }

    public LevelOfConfidenceCode getLevelOfConfidenceCode() {
        // ATO-98: This should only ever be null if a session was in progress during release.
        if (levelOfConfidenceCode == null) {
            levelOfConfidenceCode = levelOfConfidence.getDefaultCode();
        }
        return levelOfConfidenceCode;
    }

    public CredentialTrustLevel getCredentialTrustLevel() {
        return credentialTrustLevel;
    }

    public LevelOfConfidence getLevelOfConfidence() {
        return levelOfConfidence;
    }

    public boolean identityRequired() {
        return !levelOfConfidence.equals(LevelOfConfidence.NONE);
    }

    public boolean mfaRequired() {
        return credentialTrustLevel.equals(CredentialTrustLevel.MEDIUM_LEVEL);
    }

    @Override
    public String toString() {
        return Stream.concat(
                        getLevelOfConfidenceCode().stream(), getCredentialTrustLevelCode().stream())
                .map(Enum::toString)
                .collect(Collectors.joining("."));
    }

    @Override
    public boolean equals(Object obj) {
        if (obj instanceof VectorOfTrust other) {
            return this.levelOfConfidence.equals(other.levelOfConfidence)
                    && this.credentialTrustLevel.equals(other.credentialTrustLevel);
        }

        return false;
    }

    @Override
    public int hashCode() {
        return Objects.hash(levelOfConfidence, credentialTrustLevel);
    }

    @Override
    public int compareTo(@NotNull VectorOfTrust other) {
        return Comparator.comparing((VectorOfTrust vot) -> vot.levelOfConfidence)
                .thenComparing((VectorOfTrust vot) -> vot.credentialTrustLevel)
                .compare(this, other);
    }
}
