package uk.gov.di.authentication.sharedtest.matchers;

import org.hamcrest.Description;
import org.hamcrest.Matcher;
import org.hamcrest.TypeSafeDiagnosingMatcher;

public class StringLengthMatcher extends TypeSafeDiagnosingMatcher<String> {

    private final Matcher<Integer> matcher;

    private StringLengthMatcher(Matcher<Integer> matcher) {
        this.matcher = matcher;
    }

    @Override
    protected boolean matchesSafely(String item, Description mismatchDescription) {
        boolean matched = matcher.matches(item.length());

        if (!matched) {
            mismatchDescription.appendText(description(item.length()));
        }

        return matched;
    }

    @Override
    public void describeTo(Description description) {
        description.appendDescriptionOf(matcher);
    }

    private String description(Integer value) {
        return "a string with length: " + value;
    }

    public static StringLengthMatcher withLength(final Matcher<Integer> expected) {
        return new StringLengthMatcher(expected);
    }
}
