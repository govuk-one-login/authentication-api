package uk.gov.di.orchestration.shared.extensions.java.util.Collection;

import manifold.ext.rt.api.Extension;
import manifold.ext.rt.api.This;

import java.util.Collection;
import java.util.Objects;
import java.util.function.Function;
import java.util.stream.Collectors;

@Extension
public class CollectionExt {
    public static <E> boolean isNullOrEmpty(@This Collection<E> collection) {
        return Objects.isNull(collection) || collection.isEmpty();
    }

    public static <E, F> String format(@This Collection<E> collection) {
        return collection.format("", Function.identity());
    }

    public static <E, F> String format(@This Collection<E> collection, String delimiter) {
        return collection.format(delimiter, Function.identity());
    }

    public static <E, F> String format(
            @This Collection<E> collection, Function<? super E, F> formatter) {
        return collection.format("", formatter);
    }

    public static <E, F> String format(
            @This Collection<E> collection, String delimiter, Function<? super E, F> formatter) {
        return collection.stream()
                .map(formatter)
                .map(F::toString)
                .collect(Collectors.joining(delimiter));
    }
}
