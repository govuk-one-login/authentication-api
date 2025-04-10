package uk.gov.di.authentication.shared.entity;

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
    }
}
