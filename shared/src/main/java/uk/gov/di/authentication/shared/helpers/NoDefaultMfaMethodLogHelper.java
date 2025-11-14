package uk.gov.di.authentication.shared.helpers;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethod;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

public class NoDefaultMfaMethodLogHelper {

    private static final Logger LOG = LogManager.getLogger(NoDefaultMfaMethodLogHelper.class);

    public static void logNoDefaultMfaMethodDebug(List<MFAMethod> mfaMethods) {
        logNoDefaultMfaMethodDebug(mfaMethods, null);
    }

    public static void logNoDefaultMfaMethodDebug(
            List<MFAMethod> mfaMethods, Boolean isUserMigrated) {
        try {
            var mfaMethodCount = mfaMethods.size();
            var mfaMethodPriorityTypePairs =
                    mfaMethods.stream()
                            .map(
                                    m ->
                                            String.format(
                                                    "(%s,%s)",
                                                    Optional.ofNullable(m.getPriority())
                                                            .orElse("absent_attribute"),
                                                    Optional.ofNullable(m.getMfaMethodType())
                                                            .orElse("absent_attribute")))
                            .collect(Collectors.joining(", "));
            var isUserMigratedParsed =
                    isUserMigrated == null ? "unknown" : isUserMigrated.toString();

            LOG.warn(
                    "No default mfa method found for user. Is user migrated: {}, user MFA method count: {}, MFA method priority-type pairs: {}.",
                    isUserMigratedParsed,
                    mfaMethodCount,
                    mfaMethodPriorityTypePairs);
        } catch (Exception e) {
            LOG.warn(
                    "Non-fatal: Exception whilst logging 'no default mfa method' debug. Exception: {}",
                    e.getMessage(),
                    e);
        }
    }
}
