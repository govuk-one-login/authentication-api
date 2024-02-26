package uk.gov.di.orchestration.shared.entity.vectoroftrust;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.JsonAdapter;
import org.jetbrains.annotations.NotNull;
import software.amazon.awssdk.utils.Lazy;
import uk.gov.di.orchestration.shared.serialization.VotComponentAdapterFactory;

import java.text.MessageFormat;
import java.util.Comparator;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static uk.gov.di.orchestration.shared.entity.vectoroftrust.VotConstants.AUTH_EMPTY;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.VotConstants.AUTH_EQUIVALENCY_LIST;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.VotConstants.IDENT_EMPTY;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.VotConstants.IDENT_EQUIVALENCY_LIST;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.VotConstants.MAX_AUTH_ONLY_VOT;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.VotConstants.MIN_AUTH_IPVC_VOT;

/**
 * A Vector of Trust represents a combined authentication and identity trust level.
 */
public class VectorOfTrust implements Comparable<VectorOfTrust> {

    /**
     * AKA "Credential Trust Level"
     */
    @NotNull
    @Expose
    @JsonAdapter(VotComponentAdapterFactory.class)
    private final VotComponent<AuthId> authComponent;

    /**
     * AKA "Level Of Confidence"
     */
    @NotNull
    @Expose
    @JsonAdapter(VotComponentAdapterFactory.class)
    private final VotComponent<IdentId> identComponent;

    /**
     * Generate the inner normalised VoT lazily. This is used by any methods that do comparison of VoTs, namely
     * {@link VectorOfTrust#equals(Object)}, {@link VectorOfTrust#hashCode()},
     * {@link VectorOfTrust#compareTo(VectorOfTrust)}, {@link VectorOfTrust#requiresAuthOnly()},
     * {@link VectorOfTrust#requiresAuthIpvc()}. Can also be accessed externally by calling
     * {@link VectorOfTrust#getNormalised()}.
     */
    private final Lazy<VectorOfTrust> normalised;

    private static final VectorOfTrust EMPTY = new VectorOfTrust(VotComponent.empty(AuthId.class),
                                                                 VotComponent.empty(IdentId.class));

    private static final Map<VotComponent<AuthId>, VotComponent<AuthId>> AUTH_NORMALISATION_MAP =
            generateNormalisationMapFromEquivalencyList(AUTH_EQUIVALENCY_LIST);

    private static final Map<VotComponent<IdentId>, VotComponent<IdentId>> IDENT_NORMALISATION_MAP =
            generateNormalisationMapFromEquivalencyList(IDENT_EQUIVALENCY_LIST);

    public VectorOfTrust(VotComponent<AuthId> authComponent, VotComponent<IdentId> identComponent) {
        this(authComponent, identComponent, false);
    }

    private VectorOfTrust(VotComponent<AuthId> authComponent,
                          VotComponent<IdentId> identComponent,
                          boolean selfNormalise) {
        this.authComponent = authComponent;
        this.identComponent = identComponent;

        if (selfNormalise) {
            this.normalised = new Lazy<>(() -> this);
        } else {
            this.normalised = new Lazy<>(() ->
                    new VectorOfTrust(AUTH_NORMALISATION_MAP.getOrDefault(authComponent, authComponent),
                                      IDENT_NORMALISATION_MAP.getOrDefault(identComponent, identComponent),
                                      true));
        }
;
    }

    public static VectorOfTrust empty() {
        return EMPTY;
    }

    public static VectorOfTrust ofAuthComponent(VotComponent<AuthId> authComponent) {
        return new VectorOfTrust(authComponent, IDENT_EMPTY);
    }

    public static VectorOfTrust ofIdentComponent(VotComponent<IdentId> identComponent) {
        return new VectorOfTrust(AUTH_EMPTY, identComponent);
    }

    public static VectorOfTrust parse(String vectorOfTrust) {
        EnumSet<AuthId> authComponentIds = EnumSet.noneOf(AuthId.class);
        EnumSet<IdentId> identComponentIds = EnumSet.noneOf(IdentId.class);

        if (!vectorOfTrust.isEmpty()) {
            for (var componentId : vectorOfTrust.split("\\.", -1)) {
                Optional<AuthId> authId = AuthId.tryParse(componentId);
                if (authId.isPresent()) {
                    authComponentIds.add(authId.get());
                    continue;
                }

                Optional<IdentId> identId = IdentId.tryParse(componentId);
                if (identId.isPresent()) {
                    identComponentIds.add(identId.get());
                    continue;
                }

                throw new IllegalArgumentException(MessageFormat
                        .format("Unknown ID \"{0}\" in VoT \"{1}\".",
                                componentId,
                                vectorOfTrust));
            }
        }

        return new VectorOfTrust(
                new VotComponent<>(authComponentIds),
                new VotComponent<>(identComponentIds));
    }

    /**
     * Get the authentication component of this VoT. This will be un-normalised. First use
     * {@link VectorOfTrust#getNormalised()} to get a normalised equivalent VoT if you need a normalised authentication
     * component.
     * @return
     * @see VectorOfTrust#getNormalised()
     */
    public VotComponent<AuthId> getAuthComponent() {
        return authComponent;
    }

    /**
     * Get the identity component of this VoT. This will be un-normalised. First use
     * {@link VectorOfTrust#getNormalised()} to get a normalised equivalent VoT if you need a normalised identity
     * component.
     * @return
     * @see VectorOfTrust#getNormalised()
     */
    public VotComponent<IdentId> getIdentComponent() {
        return identComponent;
    }

    /**
     * Gets a normalised equivalent to this VoT. Where multiple VoTs with differing components have the same meaning,
     * calling this on both will always return VoTs with the same components.
     * @return A normalised version of this VoT. Note if the VoT has already been normalised, it will simply return a
     * reference to itself.
     * @see VotConstants#AUTH_EQUIVALENCY_LIST
     * @see VotConstants#IDENT_EQUIVALENCY_LIST
     */
    public VectorOfTrust getNormalised() {
        return normalised.getValue();
    }

    public boolean requiresAuthOnly() {
        return this.compareTo(MAX_AUTH_ONLY_VOT) <= 0;
    }

    public boolean requiresAuthIpvc() {
        return this.compareTo(MIN_AUTH_IPVC_VOT) >= 0;
    }

    /**
     * Note: Will not normalise VoT before formatting.
     */
    @Override
    public String toString() {
        return Stream
                .concat(authComponent.stream(),
                        identComponent.stream())
                .map(Enum::toString)
                .collect(Collectors.joining("."));
    }

    /**
     * Equality comparison between two VoTs is done against their normalised selves e.g. "Cl.Cm" will equal "C2.P0".
     */
    @Override
    public boolean equals(Object obj) {
        if (obj instanceof VectorOfTrust other) {
            var thisNormalised = this.getNormalised();
            var otherNormalised = other.getNormalised();
            return thisNormalised.authComponent.equals(otherNormalised.authComponent)
                    && thisNormalised.identComponent.equals(otherNormalised.identComponent);
        }

        return false;
    }

    /**
     * VoTs normalised self is used for hashing.
     */
    @Override
    public int hashCode() {
        var thisNormalised = this.getNormalised();
        return Objects.hash(thisNormalised.identComponent, thisNormalised.authComponent);
    }

    /**
     * Comparison between two VoTs is done against their normalised selves e.g. will return zero for "Cl" vs. "C1.P0".
     * VoTs are compared first by their identity component, then their authentication component.
     */
    @Override
    public int compareTo(@NotNull VectorOfTrust other) {
        return Comparator
                .comparing((VectorOfTrust vot) -> vot.identComponent)
                .thenComparing((VectorOfTrust vot) -> vot.authComponent)
                .compare(this.getNormalised(),
                         other.getNormalised());
    }

    private record KvPair<T>(T key, T value) {}

    private static <T> Map<T, T> generateNormalisationMapFromEquivalencyList(List<List<T>> equivalencyList) {
        return equivalencyList
                .stream()
                .flatMap(xs -> xs
                        .stream()
                        .skip(1)
                        .map(x -> new KvPair<>(x, xs.get(0))))
                .collect(Collectors.toMap(x -> x.key, x-> x.value));
    }
}
