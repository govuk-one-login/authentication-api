package uk.gov.di.orchestration.result;

import org.junit.jupiter.api.Test;

import static java.util.function.Function.identity;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

class ResultTest {

    @Test
    void okayResolvesValue() {
        var ok =
                Result.<String, String>ok("hello")
                        .map(String::toUpperCase)
                        .resolve(identity(), (x) -> "");

        assertThat(ok, is("HELLO"));
    }

    @Test
    void errResolvesValueWithoutApplyingMap() {
        var ok =
                Result.<String, String>err("goodbye")
                        .map(String::toUpperCase)
                        .resolve((x) -> "", identity());

        assertThat(ok, is("goodbye"));
    }
}
