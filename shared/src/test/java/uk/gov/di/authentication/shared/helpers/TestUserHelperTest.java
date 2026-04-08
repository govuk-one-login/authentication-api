package uk.gov.di.authentication.shared.helpers;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.DecryptionFailureException;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse;
import software.amazon.awssdk.services.secretsmanager.model.InvalidParameterException;
import software.amazon.awssdk.services.secretsmanager.model.InvalidRequestException;
import software.amazon.awssdk.services.secretsmanager.model.ResourceNotFoundException;
import software.amazon.awssdk.services.secretsmanager.model.SecretsManagerException;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.state.UserContext;
import uk.gov.di.authentication.sharedtest.logging.CaptureLoggingExtension;

import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.everyItem;
import static org.hamcrest.Matchers.hasItem;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.sharedtest.logging.LogEventMatcher.withMessageContaining;

class TestUserHelperTest {

    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final SecretsManagerClient mockedSecretsManagerClient =
            mock(SecretsManagerClient.class);

    private final String env = "test";
    private static final String TEST_EMAIL_ADDRESS = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final List<String> ALLOWLIST =
            List.of(
                    "testclient.user1@digital.cabinet-office.gov.uk",
                    "testclient.user1+1@hello.cabinet-office.gov.uk",
                    "^(.+)@digital.cabinet-office.gov.uk$",
                    "^(.+)@interwebs.org$",
                    "testclient.user2@internet.com");
    private TestUserHelper testUserHelper;

    @BeforeEach
    void setup() {
        when(configurationService.getLocalstackEndpointUri())
                .thenReturn(Optional.of("http://localhost:45678"));
        when(configurationService.getEnvironment()).thenReturn(env);
        testUserHelper = new TestUserHelper(mockedSecretsManagerClient, configurationService);
    }

    @RegisterExtension
    public final CaptureLoggingExtension logging =
            new CaptureLoggingExtension(TestUserHelper.class);

    @Test
    void shouldReturnTrueIfTestClientWithAllowedEmailAddress() {

        when(mockedSecretsManagerClient.getSecretValue(
                        GetSecretValueRequest.builder()
                                .secretId(String.format("/%s/test-client-email-allow-list", env))
                                .build()))
                .thenReturn(
                        GetSecretValueResponse.builder()
                                .secretString(String.join(",", ALLOWLIST))
                                .build());

        when(configurationService.isTestClientsEnabled()).thenReturn(true);

        var userContext = buildUserContext();

        assertTrue(testUserHelper.isTestJourney(userContext));
    }

    @Test
    void shouldReturnFalseIfTestClientsAreDisabled() {
        when(mockedSecretsManagerClient.getSecretValue(
                        GetSecretValueRequest.builder()
                                .secretId(String.format("/%s/test-client-email-allow-list", env))
                                .build()))
                .thenReturn(
                        GetSecretValueResponse.builder()
                                .secretString(String.join(",", ALLOWLIST))
                                .build());

        when(configurationService.isTestClientsEnabled()).thenReturn(false);

        var userContext = buildUserContext();

        assertFalse(testUserHelper.isTestJourney(userContext));
    }

    @Test
    void shouldReturnFalseIfSecretDoesNotContainEmailAddressInAllowList() {
        when(mockedSecretsManagerClient.getSecretValue(
                        GetSecretValueRequest.builder()
                                .secretId(String.format("/%s/test-client-email-allow-list", env))
                                .build()))
                .thenReturn(
                        GetSecretValueResponse.builder()
                                .secretString(
                                        String.join(
                                                ",",
                                                Collections.singletonList("test@wrong-email.com")))
                                .build());

        when(configurationService.isTestClientsEnabled()).thenReturn(true);

        var userContext = buildUserContext();

        assertFalse(testUserHelper.isTestJourney(userContext));
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
        assertTrue(TestUserHelper.emailMatchesAllowlist(email, ALLOWLIST));
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
        assertFalse(TestUserHelper.emailMatchesAllowlist(email, ALLOWLIST));
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
        assertFalse(TestUserHelper.emailMatchesAllowlist(email, List.of("$^", "[", "*")));
        assertThat(logging.events(), everyItem(withMessageContaining("PatternSyntaxException")));
    }

    @Test
    void emailShouldNotMatchRegexAllowlistWhenEmailIsNull() {
        when(mockedSecretsManagerClient.getSecretValue(
                        GetSecretValueRequest.builder()
                                .secretId(String.format("/%s/test-client-email-allow-list", env))
                                .build()))
                .thenReturn(
                        GetSecretValueResponse.builder()
                                .secretString(String.join(",", List.of("$^", "[", "*")))
                                .build());
        assertFalse(testUserHelper.isTestJourney((String) null));
        assertThat(logging.events(), everyItem(withMessageContaining("PatternSyntaxException")));
    }

    @Test
    void shouldReturnFalseForAnEmptyList() {
        assertFalse(
                TestUserHelper.emailMatchesAllowlist(TEST_EMAIL_ADDRESS, Collections.emptyList()));
        assertThat(logging.events(), everyItem(withMessageContaining("PatternSyntaxException")));
    }

    @Test
    void itShouldNotCallSecretsManagerIfTestClientsDisabled() {
        when(configurationService.isTestClientsEnabled()).thenReturn(false);

        testUserHelper.isTestJourney(buildUserContext());

        verify(mockedSecretsManagerClient, never())
                .getSecretValue(any(GetSecretValueRequest.class));
    }

    @Test
    void itShouldCacheTheSecretsManagerResponse() {
        when(configurationService.isTestClientsEnabled()).thenReturn(true);
        when(mockedSecretsManagerClient.getSecretValue(
                        GetSecretValueRequest.builder()
                                .secretId(String.format("/%s/test-client-email-allow-list", env))
                                .build()))
                .thenReturn(
                        GetSecretValueResponse.builder()
                                .secretString(String.join(",", ALLOWLIST))
                                .build());

        testUserHelper.isTestJourney(buildUserContext());
        // Call again to check previous result cached
        testUserHelper.isTestJourney(buildUserContext());

        verify(mockedSecretsManagerClient, times(1))
                .getSecretValue(any(GetSecretValueRequest.class));
    }

    @ParameterizedTest
    @ValueSource(
            classes = {
                ResourceNotFoundException.class,
                DecryptionFailureException.class,
                InvalidRequestException.class,
                InvalidParameterException.class
            })
    void shouldReturnFalseForARangeOfMisconfigurationErrors(Class<SecretsManagerException> clazz) {
        when(configurationService.isTestClientsEnabled()).thenReturn(true);
        when(mockedSecretsManagerClient.getSecretValue(
                        GetSecretValueRequest.builder()
                                .secretId(String.format("/%s/test-client-email-allow-list", env))
                                .build()))
                .thenThrow(clazz);

        assertFalse(testUserHelper.isTestJourney(buildUserContext()));
        assertThat(
                logging.events(),
                hasItem(
                        withMessageContaining(
                                "Exception when attempting to fetch allow list from secrets manager. Returning empty list.")));
        verify(mockedSecretsManagerClient, times(1))
                .getSecretValue(any(GetSecretValueRequest.class));
    }

    @Test
    void itShouldReturnFalseForNullSecretValue() {
        when(configurationService.isTestClientsEnabled()).thenReturn(true);
        when(mockedSecretsManagerClient.getSecretValue(
                        GetSecretValueRequest.builder()
                                .secretId(String.format("/%s/test-client-email-allow-list", env))
                                .build()))
                .thenReturn(GetSecretValueResponse.builder().secretString(null).build());

        assertFalse(testUserHelper.isTestJourney(buildUserContext()));
        assertThat(
                logging.events(),
                hasItem(
                        withMessageContaining(
                                "Test client allow list secret string is null or empty")));
        verify(mockedSecretsManagerClient, times(1))
                .getSecretValue(any(GetSecretValueRequest.class));
    }

    @Test
    void itShouldReturnAnEmptyListForEmptySecretValue() {
        when(configurationService.isTestClientsEnabled()).thenReturn(true);
        when(mockedSecretsManagerClient.getSecretValue(
                        GetSecretValueRequest.builder()
                                .secretId(String.format("/%s/test-client-email-allow-list", env))
                                .build()))
                .thenReturn(GetSecretValueResponse.builder().secretString("").build());

        assertFalse(testUserHelper.isTestJourney(buildUserContext()));
        assertThat(
                logging.events(),
                hasItem(
                        withMessageContaining(
                                "Test client allow list secret string is null or empty")));
        verify(mockedSecretsManagerClient, times(1))
                .getSecretValue(any(GetSecretValueRequest.class));
    }

    private UserContext buildUserContext() {
        var authSession = new AuthSessionItem().withEmailAddress(TEST_EMAIL_ADDRESS);
        return UserContext.builder(authSession).build();
    }
}
