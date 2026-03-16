package uk.gov.di.authentication.utils.services.bulkemailsender;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.entity.BulkEmailStatus;
import uk.gov.di.authentication.shared.entity.BulkEmailUserSendMode;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.BulkEmailUsersService;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.NotificationService;
import uk.gov.service.notify.NotificationClientException;

import java.util.Map;
import java.util.Optional;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.shared.entity.NotificationType.INTERNATIONAL_NUMBERS_FORCED_MFA_RESET_BULK_EMAIL;

class InternationalNumbersForcedMfaResetBulkEmailSenderTest {

    private static final String EMAIL = "joe.bloggs@test.com";
    private static final String SUBJECT_ID = "urn:some:subject:identifier";

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
                when(dynamoService.getOptionalUserProfileFromSubject(SUBJECT_ID))
                        .thenReturn(
                                Optional.of(
                                        new UserProfile()
                                                .withSubjectID(SUBJECT_ID)
                                                .withEmail(EMAIL)));

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
