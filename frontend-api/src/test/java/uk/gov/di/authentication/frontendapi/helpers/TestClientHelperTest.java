package uk.gov.di.authentication.frontendapi.helpers;

import com.nimbusds.oauth2.sdk.id.ClientID;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.exceptions.ClientNotFoundException;
import uk.gov.di.authentication.shared.helpers.IdGenerator;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.state.UserContext;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class TestClientHelperTest {

    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private static final String TEST_EMAIL_ADDRESS = "joe.bloggs@digital.cabinet-office.gov.uk";

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

    private UserContext buildUserContext(boolean isTestClient, List<String> allowedEmails) {
        var clientRegistry =
                new ClientRegistry()
                        .withClientID(new ClientID().getValue())
                        .withClientName("some-client")
                        .withTestClient(isTestClient)
                        .withTestClientEmailAllowlist(allowedEmails);
        return UserContext.builder(
                        new Session(IdGenerator.generate()).setEmailAddress(TEST_EMAIL_ADDRESS))
                .withClient(clientRegistry)
                .build();
    }
}
