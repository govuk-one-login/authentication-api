package uk.gov.di.authentication.shared.helpers;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.shared.exceptions.ClientNotFoundException;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.state.UserContext;

import java.util.List;
import java.util.Objects;
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
            return false;
        }
        var clientRegistry =
                userContext
                        .getClient()
                        .orElseThrow(() -> new ClientNotFoundException("Could not find client"));

        var isTestClientWithAllowedEmail =
                (clientRegistry.isTestClient()
                        && emailMatchesAllowlist(
                                userContext.getAuthSession().getEmailAddress(),
                                clientRegistry.getTestClientEmailAllowlist()));

        if (isTestClientWithAllowedEmail) {
            LOG.info("Is request from a test client with a test client email address: true");
        }

        return isTestClientWithAllowedEmail;
    }

    public static boolean emailMatchesAllowlist(String emailAddress, List<String> regexAllowList) {
        if (Objects.isNull(emailAddress)) {
            return false;
        }
        for (String allowedEmailEntry : regexAllowList) {
            try {
                if (allowedEmailEntry.startsWith("^") && allowedEmailEntry.endsWith("$")) {
                    if (Pattern.matches(allowedEmailEntry, emailAddress)) {
                        return true;
                    }
                } else if (Objects.equals(emailAddress, allowedEmailEntry)) {
                    return true;
                }
            } catch (PatternSyntaxException e) {
                LOG.warn("PatternSyntaxException for: {}", allowedEmailEntry);
            }
        }
        return false;
    }
}
