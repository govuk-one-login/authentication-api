package uk.gov.di.orchestration.result;

import java.util.function.Function;

public record Err<T, E>(E value) implements Result<T, E> {
    @Override
    public <U> Result<U, E> map(Function<T, U> mapper) {
        return new Err<>(value);
    }

    @Override
    public <U> U resolve(Function<T, U> okMap, Function<E, U> errMap) {
        return errMap.apply(value);
    }
}
