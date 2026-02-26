package uk.gov.di.orchestration.shared.helpers;

import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static uk.gov.di.orchestration.shared.helpers.InputSanitiser.sanitiseBase64;

// QualityGateUnitTest
class InputSanitiserTest {

    // QualityGateRegressionTest
    @Test
    void shouldStripNonBase64Characters() {
        assertThat(sanitiseBase64("${foo.bar}"), is(Optional.empty()));
    }

    // QualityGateRegressionTest
    @Test
    void shouldIgnoreBase64Inputs() {
        var id = IdGenerator.generate();
        assertThat(sanitiseBase64(id), is(Optional.of(id)));
    }
}
