package uk.gov.di.orchestration.sharedtest.matchers;

import org.hamcrest.Description;
import org.hamcrest.TypeSafeMatcher;
import org.opentest4j.AssertionFailedError;
import uk.gov.di.orchestration.result.Err;
import uk.gov.di.orchestration.result.Ok;
import uk.gov.di.orchestration.result.Result;

import java.util.Objects;
import java.util.function.Predicate;

public class ResultMatcher<T, U> extends TypeSafeMatcher<Result<T, U>> {

    private final Predicate<T> okPredicate;
    private final Predicate<U> errPredicate;

    private ResultMatcher(Predicate<T> okPredicate, Predicate<U> errPredicate) {
        this.okPredicate = okPredicate;
        this.errPredicate = errPredicate;
    }

    @Override
    protected boolean matchesSafely(Result<T, U> item) {
        if (item instanceof Ok<T, U> ok) {
            return okPredicate.test(ok.value());
        }

        if (item instanceof Err<T, U> err) {
            return errPredicate.test(err.value());
        }

        return false;
    }

    @Override
    public void describeTo(Description description) {}

    public static <T, U> ResultMatcher<T, U> okWithValue(T value) {
        return new ResultMatcher<>(
                (actual) -> Objects.equals(value, actual), failWithMessage("Expected Ok, was Err"));
    }

    public static <T, U> ResultMatcher<T, U> errWithValue(T value) {
        return new ResultMatcher<>(
                failWithMessage("Expected Err, was Ok"), (actual) -> Objects.equals(value, actual));
    }

    private static <T> Predicate<T> failWithMessage(String message) {
        return (input) -> {
            throw new AssertionFailedError(message);
        };
    }
}
