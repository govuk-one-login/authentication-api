package uk.gov.di.orchestration.result;

import java.util.concurrent.Callable;
import java.util.function.Function;

public sealed interface Result<T, E> permits Ok, Err {

    boolean isFailure();

    boolean isSuccess();

    E getError();

    T getValue();

    static <T, E> Result<T, E> ok(T value) {
        return new Ok<>(value);
    }

    static <T, E> Result<T, E> err(E err) {
        return new Err<>(err);
    }

    static <T, E extends Exception> Result<T, E> wrapCheckedInResult(Callable<T> func) {
        try {
            return new Ok<>(func.call());
        } catch (Exception e) {
            // Casting required
            return new Err<>((E) e);
        }
    }

    <U> Result<U, E> map(Function<T, U> mapper);

    <U> U resolve(Function<T, U> okMap, Function<E, U> errMap);
}
