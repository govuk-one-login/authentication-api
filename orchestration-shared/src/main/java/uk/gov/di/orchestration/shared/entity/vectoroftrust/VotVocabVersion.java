package uk.gov.di.orchestration.shared.entity.vectoroftrust;

import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

import static uk.gov.di.orchestration.shared.entity.vectoroftrust.VotConstants.C_EMPTY;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.VotConstants.C_LOW;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.VotConstants.C_LOW_LEGACY;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.VotConstants.C_MEDIUM;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.VotConstants.C_MEDIUM_LEGACY;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.VotConstants.P_EMPTY;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.VotConstants.P_HMRC200;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.VotConstants.P_HMRC250;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.VotConstants.P_MEDIUM;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.VotConstants.P_NONE;

/**
 * Enum representing various VoT Vocabulary Versions. Different versions may represent revision to the vocabulary of IDs
 * allowed in a VoT or special vocabularies e.g. for HMRC.
 */
public enum VotVocabVersion {
    V2(
            Set.of(C_EMPTY, C_LOW, C_MEDIUM),
            Set.of(P_EMPTY, P_NONE, P_MEDIUM),
            Map.of(C_EMPTY, C_MEDIUM,
                   C_LOW_LEGACY, C_LOW,
                   C_MEDIUM_LEGACY, C_MEDIUM),
            Map.of(P_EMPTY, P_NONE),
            (VectorOfTrust vot) -> !vot.identComponent().equals(P_MEDIUM)
                    || vot.authComponent().equals(C_MEDIUM),
            (VtrRequest vtr) -> vtr.stream().allMatch(vot -> vot.identComponent().equals(P_MEDIUM))
                    || vtr.stream().noneMatch(vot -> vot.identComponent().equals(P_MEDIUM))),
    V1(
            Set.of(C_EMPTY, C_LOW_LEGACY, C_MEDIUM_LEGACY),
            Set.of(P_EMPTY, P_NONE, P_MEDIUM),
            Map.of(C_EMPTY, C_MEDIUM_LEGACY,
                   C_LOW, C_LOW_LEGACY,
                   C_MEDIUM, C_MEDIUM_LEGACY),
            Map.of(P_EMPTY, P_NONE),
            (VectorOfTrust vot) -> !vot.identComponent().equals(P_MEDIUM)
                    || vot.authComponent().equals(C_MEDIUM_LEGACY),
            (VtrRequest vtr) -> vtr.stream().allMatch(vot -> vot.identComponent().equals(P_MEDIUM))
                    || vtr.stream().noneMatch(vot -> vot.identComponent().equals(P_MEDIUM))),
    V2_HMRC(
            Set.of(C_EMPTY, C_LOW, C_MEDIUM),
            Set.of(P_EMPTY, P_NONE, P_HMRC200, P_HMRC250),
            Map.of(C_EMPTY, C_MEDIUM,
                   C_LOW_LEGACY, C_LOW,
                   C_MEDIUM_LEGACY, C_MEDIUM),
            Map.of(P_EMPTY, P_NONE),
            (VectorOfTrust vot) -> !vot.identComponent().equals(P_MEDIUM)
                    || vot.authComponent().equals(C_MEDIUM),
            (VtrRequest vtr) -> true),
    V1_HMRC(
            Set.of(C_EMPTY, C_LOW_LEGACY, C_MEDIUM_LEGACY),
            Set.of(P_EMPTY, P_NONE, P_HMRC200, P_HMRC250),
            Map.of(C_EMPTY, C_MEDIUM_LEGACY,
                   C_LOW, C_LOW_LEGACY,
                   C_MEDIUM, C_MEDIUM_LEGACY),
            Map.of(P_EMPTY, P_NONE),
            (VectorOfTrust vot) -> !vot.identComponent().equals(P_MEDIUM)
                    || vot.authComponent().equals(C_MEDIUM_LEGACY),
            (VtrRequest vtr) -> true);

    private final Set<VotComponent<AuthId>> validCredentials;
    private final Set<VotComponent<IdentId>> validIdentities;
    private final Map<VotComponent<AuthId>, VotComponent<AuthId>> normaliseCredentials;
    private final Map<VotComponent<IdentId>, VotComponent<IdentId>> normaliseIdentities;
    private final Function<VectorOfTrust, Boolean> vectorValidator;
    private final Function<VtrRequest, Boolean> requestValidator;

    VotVocabVersion(Set<VotComponent<AuthId>> validCredentials,
                    Set<VotComponent<IdentId>> validIdentities,
                    Map<VotComponent<AuthId>, VotComponent<AuthId>> normaliseCredentials,
                    Map<VotComponent<IdentId>, VotComponent<IdentId>> normaliseIdentities,
                    Function<VectorOfTrust, Boolean> vectorValidator,
                    Function<VtrRequest, Boolean> requestValidator) {
        // The below checks are just here to make sure if the above enum constants are edited, that the validation /
        // normalisation rules are still logically consistent.
        // START
        if (!validCredentials.contains(C_EMPTY) || !validIdentities.contains(P_EMPTY)) {
            throw new IllegalArgumentException("Valid set must contain empty component.");
        }

        if (!validCredentials.containsAll(normaliseCredentials.values()) ||
            !validIdentities.containsAll(normaliseIdentities.values())) {
            throw new IllegalArgumentException("Normalisation map values must be in valid set.");
        }

        var validCredentialsWithoutEmpty = validCredentials
                .stream()
                .filter(x -> !x.equals(C_EMPTY))
                .toList();
        var validIdentitiesWithoutEmpty = validIdentities
                .stream()
                .filter(x -> !x.equals(P_EMPTY))
                .toList();

        if (!Collections.disjoint(validCredentialsWithoutEmpty, normaliseCredentials.keySet()) ||
            !Collections.disjoint(validIdentitiesWithoutEmpty, normaliseIdentities.keySet())) {
            throw new IllegalArgumentException("Normalisation map keys must be empty component or not be in valid set.");
        }

        if (normaliseCredentials.containsValue(C_EMPTY) || normaliseIdentities.containsValue(P_EMPTY)) {
            throw new IllegalArgumentException("Normalisation map values must not include empty component.");
        }

        if (!normaliseCredentials.containsKey(C_EMPTY) || !normaliseIdentities.containsKey(P_EMPTY)) {
            throw new IllegalArgumentException("Normalisation map keys must include empty component.");
        }
        // END

        this.validCredentials = validCredentials.stream().beginWith(C_EMPTY).collect(Collectors.toSet());
        this.validIdentities = validIdentities.stream().beginWith(P_EMPTY).collect(Collectors.toSet());
        this.normaliseCredentials = normaliseCredentials;
        this.normaliseIdentities = normaliseIdentities;
        this.vectorValidator = vectorValidator;
        this.requestValidator = requestValidator;
    }

    /**
     * Validate a VTR against this VoT Vocabulary Version.
     * @param request VTR request to be validated.
     * @return True IFF VTR request was successfully validated.
     */
    public boolean validateRequest(VtrRequest request) {
        return requestValidator.apply(request)
                && request.stream().allMatch(this::validateVector);
    }

    private boolean validateVector(VectorOfTrust vectorOfTrust) {
        var credentialComponent = vectorOfTrust.authComponent();
        var identityComponent = vectorOfTrust.identComponent();

        return vectorValidator.apply(vectorOfTrust)
                && validateAuth(credentialComponent)
                && validateIdent(identityComponent);
    }

    private boolean validateAuth(VotComponent<AuthId> credentialComponent) {
        return validCredentials.contains(credentialComponent);
    }

    private boolean validateIdent(VotComponent<IdentId> identityComponent) {
        return validIdentities.contains(identityComponent);
    }

    /**
     * Normalise an {@link VectorOfTrust} to this VoT Vocabulary Version. If the VoT has empty components (i.e.
     * is un-normalised) these will be filled with defaults provided by the version. If the components of the input VoT
     * contain components incompatible with this version, a translation will be attempted, but no validation is done.
     * @param vector VoT to be normalised.
     * @return A version normalised VoT.
     */
    public VectorOfTrust normaliseVector(VectorOfTrust vector) {
        return new VectorOfTrust(normaliseAuth(vector.authComponent()),
                                 normaliseIdent(vector.identComponent()));
    }

    /**
     * Normalise an authentication {@link VotComponent} to this VoT Vocabulary Version.
     * @param authComponent VoT authentication component to normalise.
     * @return A version normalised authentication component.
     * @see #normaliseVector(VectorOfTrust)
     */
    public VotComponent<AuthId> normaliseAuth(VotComponent<AuthId> authComponent) {
        return normaliseCredentials.getOrDefault(authComponent, authComponent);
    }

    /**
     * Normalise an identity {@link VotComponent} to this VoT Vocabulary Version.
     * @param identComponent VoT identity component to normalise.
     * @return A version normalised identity component.
     * @see #normaliseVector(VectorOfTrust)
     */
    public VotComponent<IdentId> normaliseIdent(VotComponent<IdentId> identComponent) {
        return normaliseIdentities.getOrDefault(identComponent, identComponent);
    }

    /**
     * Check if a normalised {@link VotComponent} requires
     * @param vector
     * @return
     */
    public boolean requiresIdentityCheck(VectorOfTrust vector) {
        return !vector.identComponent().equals(P_NONE);
    }
}
