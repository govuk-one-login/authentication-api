package uk.gov.di.authentication.frontendapi.helpers;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.shared.exceptions.ClientNotFoundException;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.state.UserContext;

public class TestClientHelper {

    private static final Logger LOG = LogManager.getLogger(TestClientHelper.class);

    private TestClientHelper() {}

    public static boolean isTestClientWithAllowedEmail(
            UserContext userContext, ConfigurationService configurationService)
            throws ClientNotFoundException {
        if (configurationService.isTestClientsEnabled()) {
            LOG.warn("TestClients are ENABLED");
        } else {
            LOG.info("TestClients are Disabled");
            return false;
        }
        var clientRegistry =
                userContext
                        .getClient()
                        .orElseThrow(() -> new ClientNotFoundException(userContext.getSession()));

        var isTestClientWithAllowedEmail =
                clientRegistry.isTestClient()
                        && clientRegistry
                                .getTestClientEmailAllowlist()
                                .contains(userContext.getSession().getEmailAddress());

        LOG.info(
                "Is request from a test client with a test client email address: {}",
                isTestClientWithAllowedEmail);

        return isTestClientWithAllowedEmail;
    }
}
