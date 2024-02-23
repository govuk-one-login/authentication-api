package uk.gov.di.orchestration.shared.entity.vectoroftrust;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.JsonAdapter;
import org.jetbrains.annotations.NotNull;
import uk.gov.di.orchestration.shared.serialization.VotComponentAdapterFactory;

import java.text.MessageFormat;
import java.util.EnumSet;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static uk.gov.di.orchestration.shared.entity.vectoroftrust.VotConstants.C_EMPTY;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.VotConstants.P_EMPTY;

/**
 * A Vector of Trust represents a combined authentication and identity trust level. Vectors of Trust can be both
 * normalised and un-normalised, with un-normalised VoTs having one or more empty components that indicate the requester
 * is delegating to use to pick a trust level for that aspect of trust.
 * @param authComponent Credential authentication component. AKA "Credential Trust Level".
 * @param identComponent Identity verification component. AKA "Level Of Confidence".
 */
public record VectorOfTrust(
        @NotNull
        @Expose
        @JsonAdapter(VotComponentAdapterFactory.class)
        VotComponent<AuthId> authComponent,
        @NotNull
        @Expose
        @JsonAdapter(VotComponentAdapterFactory.class)
        VotComponent<IdentId> identComponent) {

    private static final VectorOfTrust EMPTY = new VectorOfTrust(VotComponent.empty(AuthId.class),
                                                                 VotComponent.empty(IdentId.class));

    public static VectorOfTrust empty() {
        return EMPTY;
    }

    public static VectorOfTrust ofAuthComponent(VotComponent<AuthId> authComponent) {
        return new VectorOfTrust(authComponent, P_EMPTY);
    }

    public static VectorOfTrust ofIdentComponent(VotComponent<IdentId> identComponent) {
        return new VectorOfTrust(C_EMPTY, identComponent);
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

                throw new IllegalArgumentException(MessageFormat.format(
                        "Unknown ID \"{0}\" in Vector-Of-Trust \"{1}\".",
                        componentId,
                        vectorOfTrust));
            }
        }

        return new VectorOfTrust(
                new VotComponent<>(authComponentIds),
                new VotComponent<>(identComponentIds));
    }

    @Override
    public String toString() {
        return Stream
                .concat(authComponent.stream(),
                        identComponent.stream())
                .map(Enum::toString)
                .collect(Collectors.joining("."));
    }
}
