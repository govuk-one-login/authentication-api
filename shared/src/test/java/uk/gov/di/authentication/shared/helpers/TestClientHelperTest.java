package uk.gov.di.authentication.shared.helpers;

import com.nimbusds.oauth2.sdk.id.ClientID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse;
import software.amazon.awssdk.services.secretsmanager.model.ResourceNotFoundException;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.exceptions.ClientNotFoundException;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.state.UserContext;
import uk.gov.di.authentication.sharedtest.logging.CaptureLoggingExtension;

import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.everyItem;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.sharedtest.logging.LogEventMatcher.withMessageContaining;

class TestClientHelperTest {

    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final String env = "test";
    private static final String TEST_EMAIL_ADDRESS = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final List<String> ALLOWLIST =
            List.of(
                    "testclient.user1@digital.cabinet-office.gov.uk",
                    "testclient.user1+1@hello.cabinet-office.gov.uk",
                    "^(.+)@digital.cabinet-office.gov.uk$",
                    "^(.+)@interwebs.org$",
                    "testclient.user2@internet.com");

    @BeforeEach
    void setup() {
        when(configurationService.getLocalstackEndpointUri())
                .thenReturn(Optional.of("http://localhost:45678"));
        when(configurationService.getEnvironment()).thenReturn(env);
    }

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

    @Test
    void itShouldFetchTheSecretListFromSecretsManger() {
        var mockedSecretsManagerClient = mock(SecretsManagerClient.class);
        when(mockedSecretsManagerClient.getSecretValue(
                        GetSecretValueRequest.builder()
                                .secretId(String.format("/%s/test-client-email-allow-list", env))
                                .build()))
                .thenReturn(
                        GetSecretValueResponse.builder()
                                .secretString(String.join(",", ALLOWLIST))
                                .build());

        var testClientHelper = new TestClientHelper(mockedSecretsManagerClient);

        assertEquals(
                ALLOWLIST,
                testClientHelper.getEmailAllowListFromSecretsManager(configurationService));
    }

    @Test
    void itShouldCacheTheSecretsManagerResponse() {
        var mockedSecretsManagerClient = mock(SecretsManagerClient.class);
        when(mockedSecretsManagerClient.getSecretValue(
                        GetSecretValueRequest.builder()
                                .secretId(String.format("/%s/test-client-email-allow-list", env))
                                .build()))
                .thenReturn(
                        GetSecretValueResponse.builder()
                                .secretString(String.join(",", ALLOWLIST))
                                .build());

        var testClientHelper = new TestClientHelper(mockedSecretsManagerClient);
        assertEquals(
                ALLOWLIST,
                testClientHelper.getEmailAllowListFromSecretsManager(configurationService));
        // Call again to check previous result cached
        testClientHelper.getEmailAllowListFromSecretsManager(configurationService);
        verify(mockedSecretsManagerClient, times(1))
                .getSecretValue(any(GetSecretValueRequest.class));
    }

    @Test
    void itShouldReturnAnEmptyListForResourceNotFoundException() {
        var mockedSecretsManagerClient = mock(SecretsManagerClient.class);
        when(mockedSecretsManagerClient.getSecretValue(
                        GetSecretValueRequest.builder()
                                .secretId(String.format("/%s/test-client-email-allow-list", env))
                                .build()))
                .thenThrow(ResourceNotFoundException.class);

        var testClientHelper = new TestClientHelper(mockedSecretsManagerClient);

        assertEquals(
                List.of(),
                testClientHelper.getEmailAllowListFromSecretsManager(configurationService));
    }

    @Test
    void itShouldReturnAnEmptyListForNullSecretValue() {
        var mockedSecretsManagerClient = mock(SecretsManagerClient.class);
        when(mockedSecretsManagerClient.getSecretValue(
                        GetSecretValueRequest.builder()
                                .secretId(String.format("/%s/test-client-email-allow-list", env))
                                .build()))
                .thenReturn(GetSecretValueResponse.builder().secretString(null).build());

        var testClientHelper = new TestClientHelper(mockedSecretsManagerClient);

        assertEquals(
                List.of(),
                testClientHelper.getEmailAllowListFromSecretsManager(configurationService));
    }

    @Test
    void itShouldReturnAnEmptyListForEmptySecretValue() {
        var mockedSecretsManagerClient = mock(SecretsManagerClient.class);
        when(mockedSecretsManagerClient.getSecretValue(
                        GetSecretValueRequest.builder()
                                .secretId(String.format("/%s/test-client-email-allow-list", env))
                                .build()))
                .thenReturn(GetSecretValueResponse.builder().secretString("").build());

        var testClientHelper = new TestClientHelper(mockedSecretsManagerClient);

        assertEquals(
                List.of(),
                testClientHelper.getEmailAllowListFromSecretsManager(configurationService));
    }

    private UserContext buildUserContext(boolean isTestClient, List<String> allowedEmails) {
        var clientRegistry =
                new ClientRegistry()
                        .withClientID(new ClientID().getValue())
                        .withClientName("some-client")
                        .withTestClient(isTestClient)
                        .withTestClientEmailAllowlist(allowedEmails);
        var authSession = new AuthSessionItem().withEmailAddress(TEST_EMAIL_ADDRESS);
        return UserContext.builder(authSession).withClient(clientRegistry).build();
    }
}
