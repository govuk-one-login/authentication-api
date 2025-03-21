package uk.gov.di.orchestration.shared.helpers;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.List;
import java.util.Objects;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

public class TestClientHelper {
    private static final Logger LOG = LogManager.getLogger(TestClientHelper.class);

    private TestClientHelper() {}

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
