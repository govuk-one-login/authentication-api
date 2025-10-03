package uk.gov.di.orchestration.result;

import java.util.function.Function;

public record Err<T, E>(E err) implements Result<T, E> {
    @Override
    public <U> Result<U, E> map(Function<T, U> mapper) {
        return new Err<>(err);
    }

    @Override
    public <U> U resolve(Function<T, U> okMap, Function<E, U> errMap) {
        return errMap.apply(err);
    }

    @Override
    public boolean isFailure() {
        return true;
    }

    @Override
    public boolean isSuccess() {
        return false;
    }

    @Override
    public T getValue() {
        throw new IllegalStateException("No value present in Err");
    }

    @Override
    public E getError() {
        return err;
    }
}
