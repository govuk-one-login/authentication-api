package uk.gov.di.accountmanagement.helpers;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.services.mfa.MFAMethodsService;
import uk.gov.di.authentication.shared.services.mfa.MfaMigrationFailureReason;
import uk.gov.di.authentication.sharedtest.logging.CaptureLoggingExtension;

import java.util.Optional;
import java.util.stream.Stream;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.shared.services.mfa.MfaMigrationFailureReason.ALREADY_MIGRATED;
import static uk.gov.di.authentication.shared.services.mfa.MfaMigrationFailureReason.NO_USER_FOUND_FOR_EMAIL;
import static uk.gov.di.authentication.shared.services.mfa.MfaMigrationFailureReason.UNEXPECTED_ERROR_RETRIEVING_METHODS;
import static uk.gov.di.authentication.sharedtest.logging.LogEventMatcher.withMessageContaining;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;

class MfaMethodsMigrationHelperTest {
    private static final String EMAIL = "email@example.com";
    private static MFAMethodsService mfaMethodsService = mock(MFAMethodsService.class);
    private static AuditContext auditContext = mock(AuditContext.class);

    @RegisterExtension
    public final CaptureLoggingExtension logging =
            new CaptureLoggingExtension(MfaMethodsMigrationHelper.class);

    private final Logger logger = LogManager.getLogger(MfaMethodsMigrationHelper.class);

    private static final String MIGRATION_SUCCESS_LOG = "MFA Methods migrated for user";

    @Test
    void shouldReturnAnEmptyAndLogWhenUserNotMigratedAndMigrationReturnsNoError() {
        var userProfile = new UserProfile().withMfaMethodsMigrated(false).withEmail(EMAIL);

        when(mfaMethodsService.migrateMfaCredentialsForUser(EMAIL)).thenReturn(Optional.empty());

        var result =
                MfaMethodsMigrationHelper.migrateMfaCredentialsForUserIfRequired(
                        userProfile, mfaMethodsService, logger);

        assertEquals(Optional.empty(), result);

        assertThat(logging.events(), hasItem(withMessageContaining(MIGRATION_SUCCESS_LOG)));
    }

    @Test
    void shouldReturnAnEmptyAndNotLogSuccesWhenUserAlreadyMigrated() {
        var userProfile = new UserProfile().withMfaMethodsMigrated(true).withEmail(EMAIL);

        var result =
                MfaMethodsMigrationHelper.migrateMfaCredentialsForUserIfRequired(
                        userProfile, mfaMethodsService, logger);

        assertEquals(Optional.empty(), result);

        assertThat(logging.events(), not(hasItem(withMessageContaining(MIGRATION_SUCCESS_LOG))));
    }

    private static Stream<Arguments> fatalMigrationErrorsToHttpStatusAndError() {
        return Stream.of(
                Arguments.of(NO_USER_FOUND_FOR_EMAIL, 404, ErrorResponse.ERROR_1056),
                Arguments.of(UNEXPECTED_ERROR_RETRIEVING_METHODS, 500, ErrorResponse.ERROR_1064));
    }

    @ParameterizedTest
    @MethodSource("fatalMigrationErrorsToHttpStatusAndError")
    void shouldReturnAppropriateApiProxyResponseWhenMigrationReturnsError(
            MfaMigrationFailureReason migrationFailureReason,
            int expectedHttpStatus,
            ErrorResponse expectedErrorResponse) {
        var userProfile = new UserProfile().withMfaMethodsMigrated(false).withEmail(EMAIL);

        when(mfaMethodsService.migrateMfaCredentialsForUser(EMAIL))
                .thenReturn(Optional.of(migrationFailureReason));

        var maybeErrorResponse =
                MfaMethodsMigrationHelper.migrateMfaCredentialsForUserIfRequired(
                        userProfile, mfaMethodsService, logger);

        assertTrue(maybeErrorResponse.isPresent());
        assertEquals(expectedHttpStatus, maybeErrorResponse.get().getStatusCode());
        assertThat(maybeErrorResponse.get(), hasJsonBody(expectedErrorResponse));

        assertThat(logging.events(), not(hasItem(withMessageContaining(MIGRATION_SUCCESS_LOG))));

        assertThat(
                logging.events(),
                hasItem(
                        withMessageContaining(
                                format(
                                        "Failed to migrate user's MFA credentials due to %s",
                                        migrationFailureReason))));
    }

    @Test
    void shouldNotReturnFailureIfMigrationFailsDueToMethodsAlreadyMigrated() {
        var userProfile = new UserProfile().withEmail(EMAIL).withMfaMethodsMigrated(false);

        when(mfaMethodsService.migrateMfaCredentialsForUser(EMAIL))
                .thenReturn(Optional.of(ALREADY_MIGRATED));

        var maybeErrorResponse =
                MfaMethodsMigrationHelper.migrateMfaCredentialsForUserIfRequired(
                        userProfile, mfaMethodsService, logger);

        assertEquals(Optional.empty(), maybeErrorResponse);

        assertThat(logging.events(), not(hasItem(withMessageContaining(MIGRATION_SUCCESS_LOG))));

        assertThat(
                logging.events(),
                hasItem(
                        withMessageContaining(
                                "Failed to migrate user's MFA credentials due to ALREADY_MIGRATED")));
    }
}
