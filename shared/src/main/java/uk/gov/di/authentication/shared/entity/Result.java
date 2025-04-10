package uk.gov.di.authentication.shared.entity;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

public sealed interface Result<F, S> permits Result.Failure, Result.Success {
    boolean isFailure();

    boolean isSuccess();

    F getFailure();

    S getSuccess();

    static <F, S> Result<F, S> failure(F value) {
        return new Failure<>(value);
    }

    static <F, S> Result<F, S> success(S value) {
        return new Success<>(value);
    }

    static <F, S> Result<F, List<S>> sequenceSuccess(List<Result<F, S>> results) {
        List<S> values = new ArrayList<>();
        for (Result<F, S> result : results) {
            if (result.isFailure()) {
                return Result.failure(result.getFailure()); // short-circuit on first failure
            } else {
                values.add(result.getSuccess());
            }
        }
        return Result.success(values);
    }

    <T> Result<F, T> map(Function<S, T> mapper);

    record Failure<F, S>(F value) implements Result<F, S> {
        @Override
        public boolean isFailure() {
            return true;
        }

        @Override
        public boolean isSuccess() {
            return false;
        }

        @Override
        public F getFailure() {
            return value;
        }

        @Override
        public S getSuccess() {
            throw new IllegalStateException("No success value present in Failure");
        }

        @Override
        public <T> Result<F, T> map(Function<S, T> mapper) {
            return new Failure<>(value);
        }
    }

    record Success<F, S>(S value) implements Result<F, S> {
        @Override
        public boolean isFailure() {
            return false;
        }

        @Override
        public boolean isSuccess() {
            return true;
        }

        @Override
        public F getFailure() {
            throw new IllegalStateException("No failure value present in Success");
        }

        @Override
        public S getSuccess() {
            return value;
        }

        @Override
        public <T> Result<F, T> map(Function<S, T> mapper) {
            return new Success<>(mapper.apply(value));
        }
    }
}
