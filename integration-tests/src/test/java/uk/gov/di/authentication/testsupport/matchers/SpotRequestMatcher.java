package uk.gov.di.authentication.testsupport.matchers;

import org.hamcrest.Description;
import org.hamcrest.TypeSafeDiagnosingMatcher;
import uk.gov.di.authentication.ipv.entity.SPOTRequest;

import java.util.function.Function;

public class SpotRequestMatcher<T> extends TypeSafeDiagnosingMatcher<SPOTRequest> {

    private final String name;
    private final Function<SPOTRequest, T> mapper;
    private final T expected;

    private SpotRequestMatcher(String name, Function<SPOTRequest, T> mapper, T expected) {
        this.name = name;
        this.mapper = mapper;
        this.expected = expected;
    }

    public static SpotRequestMatcher<String> hasAccountId(String accountId) {
        Function<SPOTRequest, String> extractAccountId = SPOTRequest::getLocalAccountId;

        return new SpotRequestMatcher<>("local account id", extractAccountId, accountId);
    }

    public static SpotRequestMatcher<String> hasSub(String sub) {
        Function<SPOTRequest, String> extractSub = SPOTRequest::getSub;

        return new SpotRequestMatcher<>("sub", extractSub, sub);
    }

    @Override
    protected boolean matchesSafely(SPOTRequest spotRequest, Description mismatchDescription) {
        var actual = mapper.apply(spotRequest);

        var matched = actual.equals(expected);

        if (!matched) {
            mismatchDescription.appendText(description(actual));
        }

        return matched;
    }

    @Override
    public void describeTo(Description description) {
        description.appendText(description(expected));
    }

    private String description(T value) {
        return "a spot request with " + name + ": " + value;
    }
}
