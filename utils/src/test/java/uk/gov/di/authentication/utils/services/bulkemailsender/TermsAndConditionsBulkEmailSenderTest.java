package uk.gov.di.authentication.utils.services.bulkemailsender;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.entity.BulkEmailStatus;
import uk.gov.di.authentication.shared.entity.BulkEmailUserSendMode;
import uk.gov.di.authentication.shared.entity.TermsAndConditions;
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
import uk.gov.di.authentication.utils.exceptions.IncludedTermsAndConditionsConfigMissingException;
import uk.gov.service.notify.NotificationClientException;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.shared.entity.NotificationType.TERMS_AND_CONDITIONS_BULK_EMAIL;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;

class TermsAndConditionsBulkEmailSenderTest {

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

    private TermsAndConditionsBulkEmailSender sender;

    @BeforeEach
    void setUp() {
        when(configurationService.getBulkUserEmailIncludedTermsAndConditions())
                .thenReturn(List.of("1.0", "1.1"));
        when(configurationService.getEnvironment()).thenReturn("test");

        sender =
                new TermsAndConditionsBulkEmailSender(
                        bulkEmailUsersService,
                        cloudwatchMetricsService,
                        configurationService,
                        notificationService,
                        auditService,
                        dynamoService);
    }

    @Nested
    class ValidateConfiguration {

        @Test
        void shouldThrowWhenIncludedTermsAndConditionsEmpty() {
            when(configurationService.getBulkUserEmailIncludedTermsAndConditions())
                    .thenReturn(List.of());
            var scopedSender =
                    new TermsAndConditionsBulkEmailSender(
                            bulkEmailUsersService,
                            cloudwatchMetricsService,
                            configurationService,
                            notificationService,
                            auditService,
                            dynamoService);

            assertThrows(
                    IncludedTermsAndConditionsConfigMissingException.class,
                    scopedSender::validateConfiguration);
        }
    }

    @Nested
    class ValidateAndSendMessage {

        @Test
        void shouldSendEmailWhenUserHasNoTermsAndConditionsAccepted()
                throws NotificationClientException {
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
                    .sendEmail(EMAIL, Map.of(), TERMS_AND_CONDITIONS_BULK_EMAIL, "");
            verify(bulkEmailUsersService).updateUserStatus(SUBJECT_ID, BulkEmailStatus.EMAIL_SENT);
            verify(auditService)
                    .submitAuditEvent(
                            eq(UtilsAuditableEvent.AUTH_BULK_EMAIL_SENT),
                            argThat(
                                    ctx ->
                                            EMAIL.equals(ctx.email())
                                                    && expectedSubjectId.equals(ctx.subjectId())),
                            eq(pair("internalSubjectId", SUBJECT_ID)),
                            eq(pair("bulk-email-type", BulkEmailType.VC_EXPIRY_BULK_EMAIL.name())));
        }

        @Test
        void shouldSendEmailWhenUserTermsAndConditionsVersionIsInIncludedList()
                throws NotificationClientException {
            when(configurationService.isBulkUserEmailEmailSendingEnabled()).thenReturn(true);
            var userProfile =
                    new UserProfile()
                            .withSubjectID(SUBJECT_ID)
                            .withEmail(EMAIL)
                            .withTermsAndConditions(new TermsAndConditions("1.0", "2024-01-01"));
            when(dynamoService.getOptionalUserProfileFromSubject(SUBJECT_ID))
                    .thenReturn(Optional.of(userProfile));

            sender.validateAndSendMessage(SUBJECT_ID, BulkEmailUserSendMode.PENDING);

            verify(notificationService)
                    .sendEmail(EMAIL, Map.of(), TERMS_AND_CONDITIONS_BULK_EMAIL, "");
            verify(bulkEmailUsersService).updateUserStatus(SUBJECT_ID, BulkEmailStatus.EMAIL_SENT);
        }

        @Test
        void shouldNotSendEmailWhenUserTermsAndConditionsVersionIsNotInIncludedList() {
            var userProfile =
                    new UserProfile()
                            .withSubjectID(SUBJECT_ID)
                            .withTermsAndConditions(new TermsAndConditions("1.5", "2024-01-01"));
            when(dynamoService.getOptionalUserProfileFromSubject(SUBJECT_ID))
                    .thenReturn(Optional.of(userProfile));

            sender.validateAndSendMessage(SUBJECT_ID, BulkEmailUserSendMode.PENDING);

            verify(bulkEmailUsersService)
                    .updateUserStatus(SUBJECT_ID, BulkEmailStatus.TERMS_ACCEPTED_RECENTLY);
            verifyNoInteractions(notificationService);
        }

        @Test
        void shouldNotSendEmailWhenSendingDisabled() {
            when(configurationService.isBulkUserEmailEmailSendingEnabled()).thenReturn(false);
            var userProfile = new UserProfile().withSubjectID(SUBJECT_ID).withEmail(EMAIL);
            when(dynamoService.getOptionalUserProfileFromSubject(SUBJECT_ID))
                    .thenReturn(Optional.of(userProfile));

            sender.validateAndSendMessage(SUBJECT_ID, BulkEmailUserSendMode.PENDING);

            verifyNoInteractions(notificationService);
            verifyNoInteractions(auditService);
            verify(bulkEmailUsersService).updateUserStatus(SUBJECT_ID, BulkEmailStatus.EMAIL_SENT);
        }

        @Test
        void shouldSetErrorStatusWhenEmailSendingFails() throws NotificationClientException {
            when(configurationService.isBulkUserEmailEmailSendingEnabled()).thenReturn(true);
            doThrow(new NotificationClientException("error"))
                    .when(notificationService)
                    .sendEmail(EMAIL, Map.of(), TERMS_AND_CONDITIONS_BULK_EMAIL, "");
            var userProfile = new UserProfile().withSubjectID(SUBJECT_ID).withEmail(EMAIL);
            when(dynamoService.getOptionalUserProfileFromSubject(SUBJECT_ID))
                    .thenReturn(Optional.of(userProfile));

            sender.validateAndSendMessage(SUBJECT_ID, BulkEmailUserSendMode.PENDING);

            verify(bulkEmailUsersService)
                    .updateUserStatus(SUBJECT_ID, BulkEmailStatus.ERROR_SENDING_EMAIL);
            verifyNoInteractions(auditService);
        }

        @Test
        void shouldSetRetryStatusForDeliveryReceiptRetries() throws NotificationClientException {
            when(configurationService.isBulkUserEmailEmailSendingEnabled()).thenReturn(true);
            var userProfile = new UserProfile().withSubjectID(SUBJECT_ID).withEmail(EMAIL);
            when(dynamoService.getOptionalUserProfileFromSubject(SUBJECT_ID))
                    .thenReturn(Optional.of(userProfile));

            sender.validateAndSendMessage(
                    SUBJECT_ID, BulkEmailUserSendMode.DELIVERY_RECEIPT_TEMPORARY_FAILURE_RETRIES);

            verify(notificationService)
                    .sendEmail(EMAIL, Map.of(), TERMS_AND_CONDITIONS_BULK_EMAIL, "");
            verify(bulkEmailUsersService)
                    .updateUserStatus(SUBJECT_ID, BulkEmailStatus.RETRY_EMAIL_SENT);
        }

        @Test
        void shouldSetAccountNotFoundStatusWhenUserNotFound() {
            when(dynamoService.getOptionalUserProfileFromSubject(SUBJECT_ID))
                    .thenReturn(Optional.empty());

            sender.validateAndSendMessage(SUBJECT_ID, BulkEmailUserSendMode.PENDING);

            verify(bulkEmailUsersService)
                    .updateUserStatus(SUBJECT_ID, BulkEmailStatus.ACCOUNT_NOT_FOUND);
            verifyNoInteractions(notificationService);
            verifyNoInteractions(auditService);
        }
    }
}
