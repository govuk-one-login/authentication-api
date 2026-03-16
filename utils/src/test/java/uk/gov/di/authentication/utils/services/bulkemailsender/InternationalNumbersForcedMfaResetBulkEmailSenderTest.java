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

import java.util.Optional;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class InternationalNumbersForcedMfaResetBulkEmailSenderTest {

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

        @Test
        void shouldUpdateStatusToAccountNotFoundWhenUserNotFound() {
            when(dynamoService.getOptionalUserProfileFromSubject(SUBJECT_ID))
                    .thenReturn(Optional.empty());

            sender.validateAndSendMessage(SUBJECT_ID, BulkEmailUserSendMode.PENDING);

            verify(bulkEmailUsersService)
                    .updateUserStatus(SUBJECT_ID, BulkEmailStatus.ACCOUNT_NOT_FOUND);
        }

        @Test
        void shouldNotUpdateStatusToAccountNotFoundWhenUserFound() {
            when(dynamoService.getOptionalUserProfileFromSubject(SUBJECT_ID))
                    .thenReturn(Optional.of(new UserProfile().withSubjectID(SUBJECT_ID)));

            sender.validateAndSendMessage(SUBJECT_ID, BulkEmailUserSendMode.PENDING);

            verify(bulkEmailUsersService, never())
                    .updateUserStatus(SUBJECT_ID, BulkEmailStatus.ACCOUNT_NOT_FOUND);
        }
    }
}
