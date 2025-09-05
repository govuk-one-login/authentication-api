package uk.gov.di.orchestration.result;

import java.util.function.Function;

public sealed interface Result<T, E> permits Ok, Err {

    static <T, E> Result<T, E> ok(T value) {
        return new Ok<>(value);
    }

    static <T, E> Result<T, E> err(E value) {
        return new Err<>(value);
    }

    <U> Result<U, E> map(Function<T, U> mapper);

    <U> U resolve(Function<T, U> okMap, Function<E, U> errMap);
}
