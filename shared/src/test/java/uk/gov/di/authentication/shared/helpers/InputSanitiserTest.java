package uk.gov.di.authentication.shared.helpers;

import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static uk.gov.di.authentication.shared.helpers.InputSanitiser.sanitiseBase64;

class InputSanitiserTest {

    @Test
    void shouldStripNonBase64Characters() {
        assertThat(sanitiseBase64("${foo.bar}"), is(Optional.empty()));
    }

    @Test
    void shouldIgnoreBase64Inputs() {
        var id = IdGenerator.generate();
        assertThat(sanitiseBase64(id), is(Optional.of(id)));
    }
}
