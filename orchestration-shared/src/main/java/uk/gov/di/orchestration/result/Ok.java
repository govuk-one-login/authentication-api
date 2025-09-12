package uk.gov.di.orchestration.result;

import java.util.function.Function;

public record Ok<T, E>(T value) implements Result<T, E> {
    @Override
    public <U> Result<U, E> map(Function<T, U> mapper) {
        return new Ok<>(mapper.apply(value));
    }

    @Override
    public <U> U resolve(Function<T, U> okMap, Function<E, U> errMap) {
        return okMap.apply(value);
    }
}
