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

    public static SpotRequestMatcher<String> hasCredential(String credential) {
        Function<SPOTRequest, String> extractCredential = SPOTRequest::getSerializedCredential;

        return new SpotRequestMatcher<>("serialized credential", extractCredential, credential);
    }

    public static SpotRequestMatcher<String> hasPairwiseIdentifier(String pairwiseIdentifier) {
        Function<SPOTRequest, String> extractPairwiseIdentifier =
                SPOTRequest::getPairwiseIdentifier;

        return new SpotRequestMatcher<>(
                "pairwise identifier", extractPairwiseIdentifier, pairwiseIdentifier);
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
