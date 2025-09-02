package uk.gov.di.orchestration.result;

import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static uk.gov.di.orchestration.sharedtest.matchers.ResultMatcher.errWithValue;
import static uk.gov.di.orchestration.sharedtest.matchers.ResultMatcher.okWithValue;

class ResultTest {

    @Test
    void okayResolvesValue() {
        var ok = Result.<String, String>ok("hello").map(String::toUpperCase);

        assertThat(ok, is(okWithValue("HELLO")));
    }

    @Test
    void errResolvesValueWithoutApplyingMap() {
        var err = Result.<String, String>err("hello").map(String::toUpperCase);

        assertThat(err, is(errWithValue("hello")));
    }
}
