package uk.gov.di.authentication.shared.helpers;

import com.nimbusds.oauth2.sdk.id.ClientID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.exceptions.ClientNotFoundException;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.state.UserContext;
import uk.gov.di.authentication.sharedtest.logging.CaptureLoggingExtension;

import java.util.Collections;
import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.everyItem;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.sharedtest.logging.LogEventMatcher.withMessageContaining;

class TestClientHelperTest {

    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private static final String TEST_EMAIL_ADDRESS = "joe.bloggs@digital.cabinet-office.gov.uk";
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

    @Test
    void shouldReturnTrueIfTestClientWithAllowedEmailAddress() throws ClientNotFoundException {
        when(configurationService.isTestClientsEnabled()).thenReturn(true);

        var userContext = buildUserContext(true, Collections.singletonList(TEST_EMAIL_ADDRESS));

        assertTrue(
                TestClientHelper.isTestClientWithAllowedEmail(userContext, configurationService));
    }

    @Test
    void shouldReturnFalseIfTestClientsAreDisabled() throws ClientNotFoundException {
        when(configurationService.isTestClientsEnabled()).thenReturn(false);

        var userContext = buildUserContext(true, Collections.singletonList(TEST_EMAIL_ADDRESS));

        assertFalse(
                TestClientHelper.isTestClientWithAllowedEmail(userContext, configurationService));
    }

    @Test
    void shouldReturnFalseIfClientIsNotATestClient() throws ClientNotFoundException {
        when(configurationService.isTestClientsEnabled()).thenReturn(true);

        var userContext = buildUserContext(false, Collections.singletonList(TEST_EMAIL_ADDRESS));

        assertFalse(
                TestClientHelper.isTestClientWithAllowedEmail(userContext, configurationService));
    }

    @Test
    void shouldReturnFalseIfClientDoesNotContainEmailAddressInAllowList()
            throws ClientNotFoundException {
        when(configurationService.isTestClientsEnabled()).thenReturn(true);

        var userContext = buildUserContext(true, Collections.singletonList("test@wrong-email.com"));

        assertFalse(
                TestClientHelper.isTestClientWithAllowedEmail(userContext, configurationService));
    }

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

    @Test
    void emailShouldNotMatchRegexAllowlistWhenEmailIsNull() {
        assertFalse(TestClientHelper.emailMatchesAllowlist(null, List.of("^$", "[", "*")));
        assertThat(logging.events(), everyItem(withMessageContaining("PatternSyntaxException")));
    }

    private UserContext buildUserContext(boolean isTestClient, List<String> allowedEmails) {
        var clientRegistry =
                new ClientRegistry()
                        .withClientID(new ClientID().getValue())
                        .withClientName("some-client")
                        .withTestClient(isTestClient)
                        .withTestClientEmailAllowlist(allowedEmails);
        var session = new Session();
        var authSession = new AuthSessionItem().withEmailAddress(TEST_EMAIL_ADDRESS);
        return UserContext.builder(authSession).withClient(clientRegistry).build();
    }
}
