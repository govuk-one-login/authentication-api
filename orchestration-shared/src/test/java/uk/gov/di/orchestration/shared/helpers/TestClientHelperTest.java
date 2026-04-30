package uk.gov.di.orchestration.shared.helpers;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import uk.gov.di.orchestration.sharedtest.logging.CaptureLoggingExtension;

import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.everyItem;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.orchestration.sharedtest.logging.LogEventMatcher.withMessageContaining;

// QualityGateUnitTest
class TestClientHelperTest {

    private static final List<String> ALLOWLIST =
            List.of(
                    "testclient.user1@digital.cabinet-office.gov.uk",
                    "testclient.user1+1@hello.cabinet-office.gov.uk",
                    "^(.+)@digital.cabinet-office.gov.uk$",
                    "^(.+)@interwebs.org$",
                    "testclient.user2@internet.com");

    @RegisterExtension
    public final CaptureLoggingExtension logging =
            new CaptureLoggingExtension(TestClientHelper.class);

    // QualityGateRegressionTest
    @ParameterizedTest
    @ValueSource(
            strings = {
                "testclient.user1@digital.cabinet-office.gov.uk",
                "testclient.user1+1@hello.cabinet-office.gov.uk",
                "abc@digital.cabinet-office.gov.uk",
                "abc.def@digital.cabinet-office.gov.uk",
                "user.one1@interwebs.org",
                "user.two2@interwebs.org",
                "testclient.user2@internet.com",
            })
    void emailShouldMatchRegexAllowlist(String email) {
        assertTrue(TestClientHelper.emailMatchesAllowlist(email, ALLOWLIST));
    }

    // QualityGateRegressionTest
    @ParameterizedTest
    @ValueSource(
            strings = {
                "testclient.user1@digital1.cabinet-office.gov.uk",
                "abc@cabinet-office.gov.uk",
                "abc.def@digital.cabinetoffice.gov.uk",
                "testclient.user3@internet.com",
                "abc.user@internet.com",
                "user.one1@interwebs.org.uk",
            })
    void emailShouldNotMatchRegexAllowlist(String email) {
        assertFalse(TestClientHelper.emailMatchesAllowlist(email, ALLOWLIST));
    }

    // QualityGateRegressionTest
    @ParameterizedTest
    @ValueSource(
            strings = {
                "testclient.user1@digital.cabinet-office.gov.uk",
                "abc@digital.cabinet-office.gov.uk",
                "abc.def@digital.cabinet-office.gov.uk",
                "user.one1@interwebs.org",
            })
    void emailShouldNotMatchRegexAllowlistWithInvalidRegex(String email) {
        assertFalse(TestClientHelper.emailMatchesAllowlist(email, List.of("$^", "[", "*")));
        assertThat(logging.events(), everyItem(withMessageContaining("PatternSyntaxException")));
    }

    // QualityGateRegressionTest
    @Test
    void emailShouldNotMatchRegexAllowlistWhenEmailIsNull() {
        assertFalse(TestClientHelper.emailMatchesAllowlist(null, List.of("^$", "[", "*")));
        assertThat(logging.events(), everyItem(withMessageContaining("PatternSyntaxException")));
    }
}
