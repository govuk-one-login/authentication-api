package uk.gov.di.orchestration.shared.entity.vectoroftrust;

import manifold.ext.delegation.rt.api.link;
import org.jetbrains.annotations.NotNull;

import java.util.Collections;
import java.util.EnumSet;
import java.util.Optional;
import java.util.Set;

import static uk.gov.di.orchestration.shared.extensions.java.lang.Enum.EnumExt.tryParse;

/**
 * A component of a {@link VectorOfTrust} representing a level of authentication or identity.
 * @param <E> ID Enum for the specific component i.e. {@link AuthId} or {@link IdentId}
 */
public class VotComponent<E extends Enum<E>> implements Set<E>, Comparable<VotComponent<E>> {

    @link Set<E> delegate;

    public VotComponent(EnumSet<E> delegate) {
        this.delegate = Collections.unmodifiableSet(delegate);
    }

    public static <T extends Enum<T>> VotComponent<T> empty(Class<T> enumClass) {
        return new VotComponent<>(EnumSet.noneOf(enumClass));
    }

    @SafeVarargs
    public static <E extends Enum<E>> VotComponent<E> of(E first, E... rest) {
        return new VotComponent<>(EnumSet.of(first, rest));
    }

    public static <T extends Enum<T>> VotComponent<T> parse(Class<T> enumClass, String component) {
        EnumSet<T> componentIds = EnumSet.noneOf(enumClass);

        if (!component.isEmpty()) {
            for (var componentId : component.split("\\.", -1)) {
                Optional<T> id = tryParse(enumClass, componentId);
                if (id.isPresent()) {
                    componentIds.add(id.get());
                    continue;
                }

                throw new IllegalArgumentException(
                        "Unknown ID \""
                                + componentId
                                + "\" in Vector-Of-Trust Component"
                                + " \""
                                + component
                                + "\".");
            }
        }

        return new VotComponent(componentIds);
    }

    @Override
    public int compareTo(@NotNull VotComponent<E> other) {
        if (this.isEmpty() || other.isEmpty()) {
            throw new IllegalArgumentException("Can't compare empty components as their default values are not yet known. Components should be normalised before comparison.");
        }

        var arr1 = this.stream().mapToInt(Enum::ordinal).toArray();
        var arr2 = other.stream().mapToInt(Enum::ordinal).toArray();

        var lim = Math.min(arr1.length, arr2.length);
        for (var i = 1; i <= lim; i++) {
            var v1 = arr1[arr1.length - i];
            var v2 = arr2[arr2.length - i];
            if (v1 != v2) {
                return v1 - v2;
            }
        }

        return arr1.length - arr2.length;
    }

    @Override
    public String toString() {
        return format(".");
    }
}
