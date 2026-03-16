package uk.gov.di.authentication.utils.services.bulkemailsender;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.entity.BulkEmailStatus;
import uk.gov.di.authentication.shared.entity.BulkEmailUserSendMode;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.SaltHelper;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.BulkEmailUsersService;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.NotificationService;
import uk.gov.di.authentication.utils.domain.BulkEmailType;
import uk.gov.di.authentication.utils.domain.UtilsAuditableEvent;
import uk.gov.service.notify.NotificationClientException;

import java.nio.ByteBuffer;
import java.util.Map;
import java.util.Optional;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.shared.entity.NotificationType.INTERNATIONAL_NUMBERS_FORCED_MFA_RESET_BULK_EMAIL;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;

class InternationalNumbersForcedMfaResetBulkEmailSenderTest {

    private static final String EMAIL = "joe.bloggs@test.com";
    private static final String SUBJECT_ID = "urn:some:subject:identifier";
    private static final String INTERNAL_SECTOR_URI = "https://test.account.gov.uk";
    private static final byte[] SALT = SaltHelper.generateNewSalt();

    private final BulkEmailUsersService bulkEmailUsersService = mock(BulkEmailUsersService.class);
    private final CloudwatchMetricsService cloudwatchMetricsService =
            mock(CloudwatchMetricsService.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final NotificationService notificationService = mock(NotificationService.class);
    private final AuditService auditService = mock(AuditService.class);
    private final DynamoService dynamoService = mock(DynamoService.class);

    private InternationalNumbersForcedMfaResetBulkEmailSender sender;

    @BeforeEach
    void setUp() {
        when(configurationService.getEnvironment()).thenReturn("test");
        sender =
                new InternationalNumbersForcedMfaResetBulkEmailSender(
                        bulkEmailUsersService,
                        cloudwatchMetricsService,
                        configurationService,
                        notificationService,
                        auditService,
                        dynamoService);
    }

    @Nested
    class ValidateAndSendMessage {

        @Nested
        class Success {

            @Test
            void shouldSendEmailAndUpdateStatus() throws NotificationClientException {
                when(configurationService.isBulkUserEmailEmailSendingEnabled()).thenReturn(true);
                when(configurationService.getInternalSectorUri()).thenReturn(INTERNAL_SECTOR_URI);
                when(dynamoService.getOrGenerateSalt(any())).thenReturn(SALT);
                var userProfile =
                        new UserProfile()
                                .withSubjectID(SUBJECT_ID)
                                .withEmail(EMAIL)
                                .withSalt(ByteBuffer.wrap(SALT));
                when(dynamoService.getOptionalUserProfileFromSubject(SUBJECT_ID))
                        .thenReturn(Optional.of(userProfile));
                var expectedSubjectId =
                        ClientSubjectHelper.getSubjectWithSectorIdentifier(
                                        userProfile, INTERNAL_SECTOR_URI, dynamoService)
                                .getValue();

                sender.validateAndSendMessage(SUBJECT_ID, BulkEmailUserSendMode.PENDING);

                verify(notificationService)
                        .sendEmail(
                                EMAIL,
                                Map.of(),
                                INTERNATIONAL_NUMBERS_FORCED_MFA_RESET_BULK_EMAIL,
                                "");
                verify(bulkEmailUsersService, times(1))
                        .updateUserStatus(SUBJECT_ID, BulkEmailStatus.EMAIL_SENT);
                verifyNoMoreInteractions(bulkEmailUsersService);
                verify(auditService)
                        .submitAuditEvent(
                                eq(UtilsAuditableEvent.AUTH_BULK_EMAIL_SENT),
                                argThat(
                                        ctx ->
                                                EMAIL.equals(ctx.email())
                                                        && expectedSubjectId.equals(
                                                                ctx.subjectId())),
                                eq(pair("internalSubjectId", SUBJECT_ID)),
                                eq(
                                        pair(
                                                "bulk-email-type",
                                                BulkEmailType
                                                        .INTERNATIONAL_NUMBERS_FORCED_MFA_RESET_BULK_EMAIL
                                                        .name())));
            }

            @Test
            void shouldNotSendAuditEventWhenEmailSendingDisabled() {
                when(configurationService.isBulkUserEmailEmailSendingEnabled()).thenReturn(false);
                when(dynamoService.getOptionalUserProfileFromSubject(SUBJECT_ID))
                        .thenReturn(
                                Optional.of(
                                        new UserProfile()
                                                .withSubjectID(SUBJECT_ID)
                                                .withEmail(EMAIL)));

                sender.validateAndSendMessage(SUBJECT_ID, BulkEmailUserSendMode.PENDING);

                verifyNoInteractions(auditService);
                verifyNoInteractions(notificationService);
                verify(bulkEmailUsersService, times(1))
                        .updateUserStatus(SUBJECT_ID, BulkEmailStatus.EMAIL_SENT);
                verifyNoMoreInteractions(bulkEmailUsersService);
            }
        }

        @Nested
        class Errors {

            @Test
            void shouldUpdateStatusToAccountNotFoundWhenUserNotFound() {
                when(dynamoService.getOptionalUserProfileFromSubject(SUBJECT_ID))
                        .thenReturn(Optional.empty());

                sender.validateAndSendMessage(SUBJECT_ID, BulkEmailUserSendMode.PENDING);

                verify(bulkEmailUsersService, times(1))
                        .updateUserStatus(SUBJECT_ID, BulkEmailStatus.ACCOUNT_NOT_FOUND);
                verifyNoMoreInteractions(bulkEmailUsersService);
                verifyNoInteractions(notificationService);
            }

            @Test
            void shouldUpdateStatusToErrorWhenNotificationClientExceptionThrown()
                    throws NotificationClientException {
                when(configurationService.isBulkUserEmailEmailSendingEnabled()).thenReturn(true);
                when(dynamoService.getOptionalUserProfileFromSubject(SUBJECT_ID))
                        .thenReturn(
                                Optional.of(
                                        new UserProfile()
                                                .withSubjectID(SUBJECT_ID)
                                                .withEmail(EMAIL)));
                doThrow(new NotificationClientException("error"))
                        .when(notificationService)
                        .sendEmail(anyString(), anyMap(), any(), anyString());

                sender.validateAndSendMessage(SUBJECT_ID, BulkEmailUserSendMode.PENDING);

                verify(bulkEmailUsersService, times(1))
                        .updateUserStatus(SUBJECT_ID, BulkEmailStatus.ERROR_SENDING_EMAIL);
                verifyNoMoreInteractions(bulkEmailUsersService);
            }
        }
    }
}
