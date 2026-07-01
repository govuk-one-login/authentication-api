package uk.gov.di.orchestration.sharedtest.matchers;

import com.nimbusds.jwt.JWTClaimsSet;
import org.hamcrest.Description;
import org.hamcrest.StringDescription;
import org.hamcrest.TypeSafeDiagnosingMatcher;
import org.opentest4j.AssertionFailedError;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.function.Function;

import static java.lang.String.format;

public class JWTClaimsSetMatcher extends TypeSafeDiagnosingMatcher<JWTClaimsSet> {
    private record ExpectedClaim<T>(
            String name, Function<JWTClaimsSet, T> extractor, T expectedValue) {}

    private final List<ExpectedClaim<?>> expectedClaims = new ArrayList<>();
    private final List<String> mismatchedClaims = new ArrayList<>();

    private JWTClaimsSetMatcher() {}

    public static JWTClaimsSetMatcher isJWTClaimSetWith() {
        return new JWTClaimsSetMatcher();
    }

    public <T> JWTClaimsSetMatcher claim(String name, T expectedValue) {
        expectedClaims.add(
                new ExpectedClaim<>(
                        name, jwtClaimsSet -> jwtClaimsSet.getClaim(name), expectedValue));
        return this;
    }

    private <T> JWTClaimsSetMatcher claim(
            String name, Function<JWTClaimsSet, T> extractor, T expectedValue) {
        expectedClaims.add(new ExpectedClaim<>(name, extractor, expectedValue));
        return this;
    }

    public JWTClaimsSetMatcher jwtID(String expectedValue) {
        return claim("jti", JWTClaimsSet::getJWTID, expectedValue);
    }

    public JWTClaimsSetMatcher issuer(String expectedValue) {
        return claim("iss", JWTClaimsSet::getIssuer, expectedValue);
    }

    public JWTClaimsSetMatcher audience(String expectedValue) {
        return claim("aud", JWTClaimsSet::getAudience, List.of(expectedValue));
    }

    public JWTClaimsSetMatcher issueTime(Date date) {
        return claim("iat", JWTClaimsSet::getIssueTime, date);
    }

    public JWTClaimsSetMatcher notBeforeTime(Date date) {
        return claim("nbf", JWTClaimsSet::getNotBeforeTime, date);
    }

    public JWTClaimsSetMatcher expirationTime(Date date) {
        return claim("exp", JWTClaimsSet::getExpirationTime, date);
    }

    @Override
    protected boolean matchesSafely(JWTClaimsSet item, Description mismatchDescription) {
        List<String> mismatches = new ArrayList<>();
        for (ExpectedClaim<?> claim : expectedClaims) {
            if (!matchClaim(claim, item, mismatches)) {
                mismatchedClaims.add(claim.name());
            }
        }

        if (!mismatches.isEmpty()) {
            mismatchDescription.appendText("{ ");
            mismatchDescription.appendText(String.join(", ", mismatches));
            mismatchDescription.appendText(" }");
            return false;
        }
        return true;
    }

    private <T> boolean matchClaim(
            ExpectedClaim<T> claim, JWTClaimsSet item, List<String> mismatches) {
        T actual = claim.extractor().apply(item);
        if (!Objects.equals(claim.expectedValue(), actual)) {
            mismatches.add(format("\"%s\": \"%s\"", claim.name(), actual));
            return false;
        }
        return true;
    }

    @Override
    public void describeTo(Description description) {
        description.appendText("{ ");
        var parts = new ArrayList<String>();
        for (var claim : expectedClaims) {
            if (mismatchedClaims.contains(claim.name())) {
                parts.add(format("\"%s\": \"%s\"", claim.name(), claim.expectedValue()));
            }
        }
        description.appendText(String.join(", ", parts));
        description.appendText(" }");
    }

    // This wrapper exists so that running the test in IntelliJ will show the Expected/Actual nicely
    public static void assertClaims(JWTClaimsSet actual, JWTClaimsSetMatcher matcher) {
        if (!matcher.matches(actual)) {
            var expected = new StringDescription();
            matcher.describeTo(expected);

            var mismatch = new StringDescription();
            matcher.describeMismatch(actual, mismatch);

            throw new AssertionFailedError(
                    "JWTClaimsSet did not match", expected.toString(), mismatch.toString());
        }
    }
}
