package uk.gov.di.authentication.utils;

import com.amazonaws.services.lambda.runtime.events.ScheduledEvent;
import com.google.gson.JsonElement;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.apache.commons.codec.binary.Hex;
import org.apache.http.client.utils.URIBuilder;
import org.joda.time.DateTime;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.shared.entity.BulkEmailStatus;
import uk.gov.di.authentication.shared.services.BulkEmailUsersService;
import uk.gov.di.authentication.shared.services.SerializationService;
import uk.gov.di.authentication.sharedtest.basetest.HandlerIntegrationTest;
import uk.gov.di.authentication.sharedtest.extensions.BulkEmailUsersExtension;
import uk.gov.di.authentication.sharedtest.extensions.NotifyStubExtension;
import uk.gov.di.authentication.utils.lambda.BulkUserEmailSenderScheduledEventHandler;

import java.security.SecureRandom;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper.assertTxmaAuditEventsSubmittedWithMatchingNames;
import static uk.gov.di.authentication.utils.domain.UtilsAuditableEvent.AUTH_BULK_EMAIL_SENT;
import static uk.gov.di.authentication.utils.domain.UtilsAuditableEvent.AUTH_BULK_RETRY_EMAIL_SENT;

public class BulkUserEmailSenderScheduledEventHandlerIntegrationTest
        extends HandlerIntegrationTest<ScheduledEvent, Void> {

    private static final String INTERNATIONAL_PHONE = "+33612345678";
    private static final String DOMESTIC_PHONE = "+447700900000";

    @RegisterExtension
    protected static final BulkEmailUsersExtension bulkEmailUsersExtension =
            new BulkEmailUsersExtension();

    @RegisterExtension
    public static final NotifyStubExtension notifyStub =
            new NotifyStubExtension(SerializationService.getInstance());

    private BulkEmailUsersService bulkEmailUsersService;

    private final ScheduledEvent scheduledEvent =
            new ScheduledEvent()
                    .withAccount("12345678")
                    .withRegion("eu-west-2")
                    .withDetailType("Scheduled Event")
                    .withSource("aws.events")
                    .withId("abcd-1234-defg-5678")
                    .withTime(DateTime.now())
                    .withResources(
                            List.of(
                                    "arn:aws:events:eu-west-2:12345678:rule/email-scheduled-campaign-rule"));

    @BeforeEach
    void beforeEach() {
        notifyStub.init();
        notifyStub.clearRequests();
        txmaAuditQueue.clear();
    }

    private void makeRequest() {
        handler.handleRequest(scheduledEvent, context);
    }

    private void assertEmailSentTo(List<JsonElement> emailsSent, String email) {
        assertThat(
                emailsSent.stream()
                        .anyMatch(
                                e ->
                                        e.getAsJsonObject()
                                                .get("email_address")
                                                .getAsString()
                                                .equals(email)),
                equalTo(true));
    }

    private void assertEmailNotSentTo(List<JsonElement> emailsSent, String email) {
        assertThat(
                emailsSent.stream()
                        .noneMatch(
                                e ->
                                        e.getAsJsonObject()
                                                .get("email_address")
                                                .getAsString()
                                                .equals(email)),
                equalTo(true));
    }

    private void setupTermsAndConditions(String sendMode) {
        setupConfig(sendMode, "TERMS_AND_CONDITIONS");
    }

    private void setupInternationalNumbers(String sendMode) {
        setupConfig(sendMode, "INTERNATIONAL_NUMBERS_FORCED_MFA_RESET");
    }

    private void setupConfig(String sendMode, String senderType) {
        var configuration = configWithSendMode(sendMode, senderType);
        handler = new BulkUserEmailSenderScheduledEventHandler(configuration);
        bulkEmailUsersService = new BulkEmailUsersService(configuration);
    }

    private int countByStatus(BulkEmailStatus status) {
        return bulkEmailUsersService.getNSubjectIdsByStatus(100, status).size();
    }

    private static IntegrationTestConfigurationService configWithSendMode(
            String sendMode, String senderType) {
        SecureRandom secureRandom = new SecureRandom();
        return new IntegrationTestConfigurationService(
                notificationsQueue,
                tokenSigner,
                docAppPrivateKeyJwtSigner,
                configurationParameters) {

            @Override
            public String getTxmaAuditQueueUrl() {
                return txmaAuditQueue.getQueueUrl();
            }

            @Override
            public Optional<String> getNotifyApiUrl() {
                return Optional.of(
                        new URIBuilder()
                                .setHost("localhost")
                                .setPort(notifyStub.getHttpPort())
                                .setScheme("http")
                                .toString());
            }

            @Override
            public String getNotifyApiKey() {
                byte[] bytes = new byte[36];
                secureRandom.nextBytes(bytes);
                return Hex.encodeHexString(bytes);
            }

            @Override
            public int getBulkUserEmailBatchQueryLimit() {
                return 5;
            }

            @Override
            public int getBulkUserEmailMaxBatchCount() {
                return 4;
            }

            @Override
            public boolean isBulkUserEmailEmailSendingEnabled() {
                return true;
            }

            @Override
            public List<String> getBulkUserEmailIncludedTermsAndConditions() {
                return List.of("1.0", "1.1", "1.2", "1.3", "1.4");
            }

            @Override
            public String getBulkEmailUserSendMode() {
                return sendMode;
            }

            @Override
            public String getBulkUserEmailSenderType() {
                return senderType;
            }
        };
    }

    @Nested
    class PendingMode {

        @Test
        void shouldSendEmailsForTermsAndConditions() {
            setupTermsAndConditions("PENDING");

            bulkEmailUsersExtension.addBulkEmailUser("1", BulkEmailStatus.PENDING);
            bulkEmailUsersExtension.addBulkEmailUser("2", BulkEmailStatus.PENDING);
            bulkEmailUsersExtension.addBulkEmailUser("3", BulkEmailStatus.EMAIL_SENT);
            bulkEmailUsersExtension.addBulkEmailUser("4", BulkEmailStatus.ERROR_SENDING_EMAIL);

            userStore.signUp("user.1@account.gov.uk", "password123", new Subject("1"), "1.0");
            userStore.signUp("user.2@account.gov.uk", "password123", new Subject("2"), "1.0");
            userStore.signUp("user.3@account.gov.uk", "password123", new Subject("3"), "1.0");
            userStore.signUp("user.4@account.gov.uk", "password123", new Subject("4"), "1.0");

            makeRequest();
            var emailsSent = notifyStub.waitForNumberOfRequests(5, 2);

            assertEmailSentTo(emailsSent, "user.1@account.gov.uk");
            assertEmailSentTo(emailsSent, "user.2@account.gov.uk");
            assertEmailNotSentTo(emailsSent, "user.3@account.gov.uk");
            assertEmailNotSentTo(emailsSent, "user.4@account.gov.uk");
            assertThat(countByStatus(BulkEmailStatus.EMAIL_SENT), equalTo(3));
            assertThat(countByStatus(BulkEmailStatus.ERROR_SENDING_EMAIL), equalTo(1));
            assertTxmaAuditEventsSubmittedWithMatchingNames(
                    txmaAuditQueue, Collections.nCopies(2, AUTH_BULK_EMAIL_SENT));
        }

        @Test
        void shouldSendEmailsForInternationalNumbers() {
            setupInternationalNumbers("PENDING");

            bulkEmailUsersExtension.addBulkEmailUser("1", BulkEmailStatus.PENDING);
            bulkEmailUsersExtension.addBulkEmailUser("2", BulkEmailStatus.PENDING);
            bulkEmailUsersExtension.addBulkEmailUser("3", BulkEmailStatus.EMAIL_SENT);
            bulkEmailUsersExtension.addBulkEmailUser("4", BulkEmailStatus.ERROR_SENDING_EMAIL);

            userStore.signUp("user.1@account.gov.uk", "password123", new Subject("1"));
            userStore.addVerifiedPhoneNumber("user.1@account.gov.uk", INTERNATIONAL_PHONE);
            userStore.signUp("user.2@account.gov.uk", "password123", new Subject("2"));
            userStore.addVerifiedPhoneNumber("user.2@account.gov.uk", INTERNATIONAL_PHONE);
            userStore.signUp("user.3@account.gov.uk", "password123", new Subject("3"));
            userStore.addVerifiedPhoneNumber("user.3@account.gov.uk", INTERNATIONAL_PHONE);
            userStore.signUp("user.4@account.gov.uk", "password123", new Subject("4"));
            userStore.addVerifiedPhoneNumber("user.4@account.gov.uk", INTERNATIONAL_PHONE);

            makeRequest();
            var emailsSent = notifyStub.waitForNumberOfRequests(5, 2);

            assertEmailSentTo(emailsSent, "user.1@account.gov.uk");
            assertEmailSentTo(emailsSent, "user.2@account.gov.uk");
            assertEmailNotSentTo(emailsSent, "user.3@account.gov.uk");
            assertEmailNotSentTo(emailsSent, "user.4@account.gov.uk");
            assertThat(countByStatus(BulkEmailStatus.EMAIL_SENT), equalTo(3));
            assertThat(countByStatus(BulkEmailStatus.ERROR_SENDING_EMAIL), equalTo(1));
            assertTxmaAuditEventsSubmittedWithMatchingNames(
                    txmaAuditQueue, Collections.nCopies(2, AUTH_BULK_EMAIL_SENT));
        }
    }

    @Nested
    class AccountNotFound {

        @Test
        void shouldMarkMissingAccountsForTermsAndConditions() {
            setupTermsAndConditions("PENDING");

            bulkEmailUsersExtension.addBulkEmailUser("999", BulkEmailStatus.PENDING);

            makeRequest();

            assertThat(countByStatus(BulkEmailStatus.ACCOUNT_NOT_FOUND), equalTo(1));
        }

        @Test
        void shouldMarkMissingAccountsForInternationalNumbers() {
            setupInternationalNumbers("PENDING");

            bulkEmailUsersExtension.addBulkEmailUser("999", BulkEmailStatus.PENDING);

            makeRequest();

            assertThat(countByStatus(BulkEmailStatus.ACCOUNT_NOT_FOUND), equalTo(1));
        }
    }

    @Nested
    class NotifyErrorRetries {

        @Test
        void shouldRetryErrorsForTermsAndConditions() {
            setupTermsAndConditions("NOTIFY_ERROR_RETRIES");

            bulkEmailUsersExtension.addBulkEmailUser("1", BulkEmailStatus.ERROR_SENDING_EMAIL);
            bulkEmailUsersExtension.addBulkEmailUser("2", BulkEmailStatus.ERROR_SENDING_EMAIL);

            userStore.signUp("user.1@account.gov.uk", "password123", new Subject("1"), "1.0");
            userStore.signUp("user.2@account.gov.uk", "password123", new Subject("2"), "1.0");

            makeRequest();
            notifyStub.waitForNumberOfRequests(5, 2);

            assertThat(countByStatus(BulkEmailStatus.EMAIL_SENT), equalTo(2));
            assertTxmaAuditEventsSubmittedWithMatchingNames(
                    txmaAuditQueue, Collections.nCopies(2, AUTH_BULK_EMAIL_SENT));
        }

        @Test
        void shouldRetryErrorsForInternationalNumbers() {
            setupInternationalNumbers("NOTIFY_ERROR_RETRIES");

            bulkEmailUsersExtension.addBulkEmailUser("1", BulkEmailStatus.ERROR_SENDING_EMAIL);
            bulkEmailUsersExtension.addBulkEmailUser("2", BulkEmailStatus.ERROR_SENDING_EMAIL);

            userStore.signUp("user.1@account.gov.uk", "password123", new Subject("1"));
            userStore.addVerifiedPhoneNumber("user.1@account.gov.uk", INTERNATIONAL_PHONE);
            userStore.signUp("user.2@account.gov.uk", "password123", new Subject("2"));
            userStore.addVerifiedPhoneNumber("user.2@account.gov.uk", INTERNATIONAL_PHONE);

            makeRequest();
            notifyStub.waitForNumberOfRequests(5, 2);

            assertThat(countByStatus(BulkEmailStatus.EMAIL_SENT), equalTo(2));
            assertTxmaAuditEventsSubmittedWithMatchingNames(
                    txmaAuditQueue, Collections.nCopies(2, AUTH_BULK_EMAIL_SENT));
        }
    }

    @Nested
    class DeliveryReceiptRetries {

        @Test
        void shouldRetryTemporaryFailuresForTermsAndConditions() {
            setupTermsAndConditions("DELIVERY_RECEIPT_TEMPORARY_FAILURE_RETRIES");

            bulkEmailUsersExtension.addBulkEmailUserWithDeliveryReceiptStatus(
                    "1", "temporary-failure", BulkEmailStatus.EMAIL_SENT);
            bulkEmailUsersExtension.addBulkEmailUserWithDeliveryReceiptStatus(
                    "2", "permanent-failure", BulkEmailStatus.EMAIL_SENT);

            userStore.signUp("user.1@account.gov.uk", "password123", new Subject("1"), "1.0");
            userStore.signUp("user.2@account.gov.uk", "password123", new Subject("2"), "1.0");

            makeRequest();
            notifyStub.waitForNumberOfRequests(5, 1);

            assertThat(countByStatus(BulkEmailStatus.RETRY_EMAIL_SENT), equalTo(1));
            assertThat(
                    bulkEmailUsersService.getBulkEmailUsers("1").get().getDeliveryReceiptStatus(),
                    equalTo(null));
            assertTxmaAuditEventsSubmittedWithMatchingNames(
                    txmaAuditQueue, List.of(AUTH_BULK_RETRY_EMAIL_SENT));
        }

        @Test
        void shouldRetryTemporaryFailuresForInternationalNumbers() {
            setupInternationalNumbers("DELIVERY_RECEIPT_TEMPORARY_FAILURE_RETRIES");

            bulkEmailUsersExtension.addBulkEmailUserWithDeliveryReceiptStatus(
                    "1", "temporary-failure", BulkEmailStatus.EMAIL_SENT);
            bulkEmailUsersExtension.addBulkEmailUserWithDeliveryReceiptStatus(
                    "2", "permanent-failure", BulkEmailStatus.EMAIL_SENT);

            userStore.signUp("user.1@account.gov.uk", "password123", new Subject("1"));
            userStore.addVerifiedPhoneNumber("user.1@account.gov.uk", INTERNATIONAL_PHONE);
            userStore.signUp("user.2@account.gov.uk", "password123", new Subject("2"));
            userStore.addVerifiedPhoneNumber("user.2@account.gov.uk", INTERNATIONAL_PHONE);

            makeRequest();
            notifyStub.waitForNumberOfRequests(5, 1);

            assertThat(countByStatus(BulkEmailStatus.RETRY_EMAIL_SENT), equalTo(1));
            assertThat(
                    bulkEmailUsersService.getBulkEmailUsers("1").get().getDeliveryReceiptStatus(),
                    equalTo(null));
            assertTxmaAuditEventsSubmittedWithMatchingNames(
                    txmaAuditQueue, List.of(AUTH_BULK_RETRY_EMAIL_SENT));
        }
    }

    @Nested
    class Validation {

        @Test
        void shouldSendEmailsToUsersWithOldTermsAndConditionsAndRejectCurrentVersions() {
            setupTermsAndConditions("PENDING");

            bulkEmailUsersExtension.addBulkEmailUser("1", BulkEmailStatus.PENDING);
            bulkEmailUsersExtension.addBulkEmailUser("2", BulkEmailStatus.PENDING);
            bulkEmailUsersExtension.addBulkEmailUser("3", BulkEmailStatus.PENDING);
            bulkEmailUsersExtension.addBulkEmailUser("4", BulkEmailStatus.PENDING);

            userStore.signUp("user.1@account.gov.uk", "password123", new Subject("1"), "1.0");
            userStore.signUp("user.2@account.gov.uk", "password123", new Subject("2"), "1.4");
            userStore.signUp("user.3@account.gov.uk", "password123", new Subject("3"), "1.5");
            userStore.signUp("user.4@account.gov.uk", "password123", new Subject("4"), null);

            makeRequest();
            notifyStub.waitForNumberOfRequests(5, 3);

            assertThat(countByStatus(BulkEmailStatus.EMAIL_SENT), equalTo(3));
            assertThat(countByStatus(BulkEmailStatus.TERMS_ACCEPTED_RECENTLY), equalTo(1));
            assertTxmaAuditEventsSubmittedWithMatchingNames(
                    txmaAuditQueue, Collections.nCopies(3, AUTH_BULK_EMAIL_SENT));
        }

        @Test
        void shouldSendEmailsToUsersWithInternationalNumbersAndRejectDomesticNumbers() {
            setupInternationalNumbers("PENDING");

            bulkEmailUsersExtension.addBulkEmailUser("1", BulkEmailStatus.PENDING);
            bulkEmailUsersExtension.addBulkEmailUser("2", BulkEmailStatus.PENDING);
            bulkEmailUsersExtension.addBulkEmailUser("3", BulkEmailStatus.PENDING);
            bulkEmailUsersExtension.addBulkEmailUser("4", BulkEmailStatus.PENDING);

            userStore.signUp("user.1@account.gov.uk", "password123", new Subject("1"));
            userStore.addVerifiedPhoneNumber("user.1@account.gov.uk", INTERNATIONAL_PHONE);
            userStore.signUp("user.2@account.gov.uk", "password123", new Subject("2"));
            userStore.addVerifiedPhoneNumber("user.2@account.gov.uk", INTERNATIONAL_PHONE);
            userStore.signUp("user.3@account.gov.uk", "password123", new Subject("3"));
            userStore.addVerifiedPhoneNumber("user.3@account.gov.uk", DOMESTIC_PHONE);
            userStore.signUp("user.4@account.gov.uk", "password123", new Subject("4"));

            makeRequest();
            notifyStub.waitForNumberOfRequests(5, 2);

            assertThat(countByStatus(BulkEmailStatus.EMAIL_SENT), equalTo(2));
            assertThat(countByStatus(BulkEmailStatus.NO_INTERNATIONAL_NUMBER), equalTo(2));
            assertTxmaAuditEventsSubmittedWithMatchingNames(
                    txmaAuditQueue, Collections.nCopies(2, AUTH_BULK_EMAIL_SENT));
        }
    }
}
