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
            var mfaMethodPriorityTypePairs = generateMfaMethodPriorityTypePairs(mfaMethods);
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

    public static void logDebugIfMfaMethodHasNullPriority(MFAMethod mfaMethod, String context) {
        logDebugIfAnyMfaMethodHasNullPriority(List.of(mfaMethod), context);
    }

    public static void logDebugIfAnyMfaMethodHasNullPriority(
            List<MFAMethod> mfaMethods, String context) {
        try {
            boolean hasNullPriority = mfaMethods.stream().anyMatch(m -> m.getPriority() == null);
            if (hasNullPriority) {
                var mfaMethodPriorityTypePairs = generateMfaMethodPriorityTypePairs(mfaMethods);
                var contextMessage = context != null ? " Context: " + context + "." : "";

                LOG.warn(
                        "MFA method with null priority identifier found. MFA method priority-type pair(s): {}.{}",
                        mfaMethodPriorityTypePairs,
                        contextMessage);
            }
        } catch (Exception e) {
            LOG.warn(
                    "Non-fatal: Exception whilst logging MFA method null priority debug. Exception: {}",
                    e.getMessage(),
                    e);
        }
    }

    private static String generateMfaMethodPriorityTypePairs(List<MFAMethod> mfaMethods) {
        return mfaMethods.stream()
                .map(
                        m ->
                                String.format(
                                        "(%s,%s)",
                                        Optional.ofNullable(m.getPriority())
                                                .orElse("absent_attribute"),
                                        Optional.ofNullable(m.getMfaMethodType())
                                                .orElse("absent_attribute")))
                .collect(Collectors.joining(", "));
    }
}
