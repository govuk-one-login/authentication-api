package uk.gov.di.orchestration.shared.extensions.java.util.stream.Stream;

import manifold.ext.rt.api.Extension;
import manifold.ext.rt.api.Self;
import manifold.ext.rt.api.This;

import java.util.stream.Stream;

@Extension
public class StreamExt {
    public static <T> @Self Stream<T> beginWith(@This Stream<T> stream, T beginElem) {
        return Stream.concat(Stream.of(beginElem), stream);
    }

    public static <T> @Self Stream<T> endWith(@This Stream<T> stream, T endElem) {
        return Stream.concat(stream, Stream.of(endElem));
    }
}
