package uk.gov.di.orchestration.shared.entity;

import com.google.gson.annotations.Expose;

import java.util.EnumSet;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static java.text.MessageFormat.format;

public class VectorOfTrust {

    public static final VectorOfTrust DEFAULT_VECTOR_OF_TRUST =
            new VectorOfTrust(CredentialTrustLevel.getDefault());

    @Expose private CredentialTrustLevel credentialTrustLevel = CredentialTrustLevel.getDefault();

    @Expose private LevelOfConfidence levelOfConfidence = LevelOfConfidence.getDefault();

    @Expose
    private CredentialTrustLevelCode credentialTrustLevelCode =
            credentialTrustLevel.getDefaultCode();

    @Expose
    private LevelOfConfidenceCode levelOfConfidenceCode = levelOfConfidence.getDefaultCode();

    public VectorOfTrust(CredentialTrustLevel credentialTrustLevel) {
        this(credentialTrustLevel.getDefaultCode());
    }

    public VectorOfTrust(
            CredentialTrustLevel credentialTrustLevel, LevelOfConfidence levelOfConfidence) {
        this(credentialTrustLevel.getDefaultCode(), levelOfConfidence.getDefaultCode());
    }

    public VectorOfTrust(CredentialTrustLevelCode credentialTrustLevelCode) {
        this(credentialTrustLevelCode, LevelOfConfidence.getDefault().getDefaultCode());
    }

    public VectorOfTrust(
            CredentialTrustLevelCode credentialTrustLevelCode,
            LevelOfConfidenceCode levelOfConfidenceCode) {
        this.credentialTrustLevelCode = credentialTrustLevelCode;
        this.levelOfConfidenceCode = levelOfConfidenceCode;
        this.credentialTrustLevel = CredentialTrustLevel.of(credentialTrustLevelCode);
        this.levelOfConfidence = LevelOfConfidence.of(levelOfConfidenceCode);
    }

    public CredentialTrustLevel getCredentialTrustLevel() {
        return credentialTrustLevel;
    }

    public LevelOfConfidence getLevelOfConfidence() {
        return levelOfConfidence;
    }

    public CredentialTrustLevelCode getCredentialTrustLevelCode() {
        return credentialTrustLevelCode;
    }

    private LevelOfConfidenceCode getLevelOfConfidenceCode() {
        return levelOfConfidenceCode;
    }

    public static VectorOfTrust parse(String vectorOfTrust) {
        EnumSet<CredentialTrustLevelId> ctlComponentIds =
                EnumSet.noneOf(CredentialTrustLevelId.class);
        EnumSet<LevelOfConfidenceId> locComponentIds = EnumSet.noneOf(LevelOfConfidenceId.class);

        if (!vectorOfTrust.isEmpty()) {
            for (var componentId : vectorOfTrust.split("\\.", -1)) {
                Optional<CredentialTrustLevelId> authId =
                        CredentialTrustLevelId.tryParse(componentId);
                Optional<LevelOfConfidenceId> identId = LevelOfConfidenceId.tryParse(componentId);

                if (authId.isPresent()) {
                    ctlComponentIds.add(authId.get());
                } else if (identId.isPresent()) {
                    locComponentIds.add(identId.get());
                } else {
                    throw new IllegalArgumentException(
                            format(
                                    "Unknown ID \"{0}\" in VoT \"{1}\".",
                                    componentId, vectorOfTrust));
                }
            }
        }

        return new VectorOfTrust(
                new CredentialTrustLevelCode(ctlComponentIds),
                new LevelOfConfidenceCode(locComponentIds));
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
}
