package uk.gov.di.authentication.shared.helpers;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethod;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.sharedtest.logging.CaptureLoggingExtension;

import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasItem;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static uk.gov.di.authentication.shared.entity.PriorityIdentifier.DEFAULT;
import static uk.gov.di.authentication.shared.helpers.NoDefaultMfaMethodLogHelper.logNoDefaultMfaMethodDebug;
import static uk.gov.di.authentication.sharedtest.logging.LogEventMatcher.withMessageContaining;

class NoDefaultMfaMethodLogHelperTest {

    @RegisterExtension
    private final CaptureLoggingExtension logging =
            new CaptureLoggingExtension(NoDefaultMfaMethodLogHelper.class);

    @Test
    void shouldHandleNullPriority() {
        var mfaMethod =
                new MFAMethod().withMfaMethodType(MFAMethodType.SMS.getValue()).withPriority(null);

        assertDoesNotThrow(() -> logNoDefaultMfaMethodDebug(List.of(mfaMethod)));

        assertThat(
                logging.events(),
                hasItem(
                        withMessageContaining(
                                "No default mfa method found for user. Is user migrated: unknown, user MFA method count: 1, MFA method priority-type pairs: (absent_attribute,SMS).")));
    }

    @Test
    void shouldCatchExceptions() {
        var mfaMethod = new ThrowingMFAMethod();

        assertDoesNotThrow(() -> logNoDefaultMfaMethodDebug(List.of(mfaMethod)));

        assertThat(
                logging.events(),
                hasItem(
                        withMessageContaining(
                                "Non-fatal: Exception whilst logging 'no default mfa method' debug. Exception: Test exception")));
    }

    @Test
    void shouldHandleNullPriorityWithIsUserMigrated() {
        var authAppMethod =
                new MFAMethod()
                        .withMfaMethodType(MFAMethodType.AUTH_APP.getValue())
                        .withPriority(null);
        var smsMethod =
                new MFAMethod()
                        .withMfaMethodType(MFAMethodType.SMS.getValue())
                        .withPriority(DEFAULT.name());

        assertDoesNotThrow(
                () -> logNoDefaultMfaMethodDebug(List.of(authAppMethod, smsMethod), true));

        assertThat(
                logging.events(),
                hasItem(
                        withMessageContaining(
                                "No default mfa method found for user. Is user migrated: true, user MFA method count: 2, MFA method priority-type pairs: (absent_attribute,AUTH_APP), (DEFAULT,SMS).")));
    }

    @Test
    void shouldCatchExceptionsWithIsUserMigrated() {
        var mfaMethod = new ThrowingMFAMethod();

        assertDoesNotThrow(() -> logNoDefaultMfaMethodDebug(List.of(mfaMethod), false));

        assertThat(
                logging.events(),
                hasItem(
                        withMessageContaining(
                                "Non-fatal: Exception whilst logging 'no default mfa method' debug. Exception: Test exception")));
    }

    @Test
    void shouldHandleNullIsUserMigrated() {
        var mfaMethod =
                new MFAMethod()
                        .withMfaMethodType(MFAMethodType.SMS.getValue())
                        .withPriority(DEFAULT.name());

        assertDoesNotThrow(() -> logNoDefaultMfaMethodDebug(List.of(mfaMethod), null));

        assertThat(
                logging.events(),
                hasItem(
                        withMessageContaining(
                                "No default mfa method found for user. Is user migrated: unknown, user MFA method count: 1, MFA method priority-type pairs: (DEFAULT,SMS).")));
    }

    private static class ThrowingMFAMethod extends MFAMethod {
        @Override
        public String getPriority() {
            throw new RuntimeException("Test exception");
        }

        @Override
        public String getMfaMethodType() {
            throw new RuntimeException("Test exception");
        }
    }
}
