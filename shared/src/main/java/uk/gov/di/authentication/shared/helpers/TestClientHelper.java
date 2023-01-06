package uk.gov.di.authentication.shared.helpers;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.shared.exceptions.ClientNotFoundException;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.state.UserContext;

import java.util.List;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

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
                (clientRegistry.isTestClient()
                        && emailMatchesAllowlist(
                                userContext.getSession().getEmailAddress(),
                                clientRegistry.getTestClientEmailAllowlist()));

        LOG.info(
                "Is request from a test client with a test client email address: {}",
                isTestClientWithAllowedEmail);

        return isTestClientWithAllowedEmail;
    }

    public static boolean emailMatchesAllowlist(String emailAddress, List<String> regexAllowList) {
        for (String regex : regexAllowList) {
            try {
                if (Pattern.matches(regex, emailAddress)) {
                    return true;
                }
            } catch (PatternSyntaxException e) {
                LOG.warn("PatternSyntaxException for: {}", regex);
            }
        }
        return false;
    }
}
