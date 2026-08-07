package uk.gov.di.orchestration.result;

import org.junit.jupiter.api.Test;

import static java.util.function.Function.identity;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static uk.gov.di.orchestration.sharedtest.matchers.ResultMatcher.errWithValue;
import static uk.gov.di.orchestration.sharedtest.matchers.ResultMatcher.okWithValue;

// QualityGateUnitTest
class ResultTest {

    // QualityGateRegressionTest
    @Test
    void mapAppliesToOkValue() {
        var ok = Result.<String, String>ok("hello").map(String::toUpperCase);

        assertThat(ok, is(okWithValue("HELLO")));
    }

    // QualityGateRegressionTest
    @Test
    void mapDoesNotApplyToErrValue() {
        var err = Result.<String, String>err("hello").map(String::toUpperCase);

        assertThat(err, is(errWithValue("hello")));
    }

    // QualityGateRegressionTest
    @Test
    void resolveAppliesToOkValue() {
        var ok =
                Result.<String, String>ok("hello")
                        .map(String::toUpperCase)
                        .resolve(identity(), identity());

        assertThat(ok, is("HELLO"));
    }

    // QualityGateRegressionTest
    @Test
    void resolveAppliesToErrValue() {
        var err =
                Result.<String, String>err("hello")
                        .map(String::toUpperCase)
                        .resolve(identity(), identity());

        assertThat(err, is("hello"));
    }
}
