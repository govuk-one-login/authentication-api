package uk.gov.di.authentication.utils;

import com.amazonaws.services.lambda.runtime.events.ScheduledEvent;
import com.google.gson.JsonElement;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.apache.commons.codec.binary.Hex;
import org.apache.http.client.utils.URIBuilder;
import org.joda.time.DateTime;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.shared.entity.BulkEmailStatus;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.BulkEmailUsersService;
import uk.gov.di.authentication.shared.services.SerializationService;
import uk.gov.di.authentication.sharedtest.basetest.HandlerIntegrationTest;
import uk.gov.di.authentication.sharedtest.extensions.BulkEmailUsersExtension;
import uk.gov.di.authentication.sharedtest.extensions.NotifyStubExtension;
import uk.gov.di.authentication.utils.lambda.BulkUserEmailSenderScheduledEventHandler;

import java.security.SecureRandom;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.IntStream;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper.assertTxmaAuditEventsReceived;
import static uk.gov.di.authentication.sharedtest.matchers.JsonMatcher.hasFieldWithValue;
import static uk.gov.di.authentication.utils.domain.UtilsAuditableEvent.BULK_EMAIL_SENT;
import static uk.gov.di.authentication.utils.domain.UtilsAuditableEvent.BULK_RETRY_EMAIL_SENT;

public class BulkUserEmailSenderScheduledEventHandlerIntegrationTest
        extends HandlerIntegrationTest<ScheduledEvent, Void> {

    @RegisterExtension
    protected static final BulkEmailUsersExtension bulkEmailUsersExtension =
            new BulkEmailUsersExtension();

    @RegisterExtension
    public static final NotifyStubExtension notifyStub =
            new NotifyStubExtension(SerializationService.getInstance());

    private BulkEmailUsersService bulkEmailUsersService;

    @BeforeEach
    void setup() {
        notifyStub.init();
        setupConfig("PENDING");
        txmaAuditQueue.clear();
    }

    @AfterEach
    void resetStub() {
        notifyStub.reset();
    }

    @Test
    void shouldSendSingleEmailWhenSinglePendingUserAndUpdateStatus() throws Json.JsonException {
        bulkEmailUsersExtension.addBulkEmailUser("1", BulkEmailStatus.PENDING);
        userStore.signUp("user.1@account.gov.uk", "password123", new Subject("1"));

        makeRequest();

        var request = notifyStub.waitForRequest(60);
        var noOfStatusEmailSent =
                bulkEmailUsersService.getNSubjectIdsByStatus(10, BulkEmailStatus.EMAIL_SENT).size();

        assertThat(request, hasFieldWithValue("email_address", equalTo("user.1@account.gov.uk")));
        assertThat(noOfStatusEmailSent, equalTo(1));
        assertTxmaAuditEventsReceived(txmaAuditQueue, List.of(BULK_EMAIL_SENT));
    }

    @Test
    void shouldSendCorrectNoOfEmailsForListOfUsersWithVariousStatusAndUpdateStatus() {
        setupDynamo();
        makeRequest();

        var emailsSent = notifyStub.waitForNumberOfRequests(60, 8);

        assertThat(
                bulkEmailUsersService.getNSubjectIdsByStatus(10, BulkEmailStatus.EMAIL_SENT).size(),
                equalTo(9));
        assertThat(
                bulkEmailUsersService
                        .getNSubjectIdsByStatus(10, BulkEmailStatus.ERROR_SENDING_EMAIL)
                        .size(),
                equalTo(2));
        assertThat(emailsSent.size(), equalTo(8));
        assertTxmaAuditEventsReceived(txmaAuditQueue, Collections.nCopies(8, BULK_EMAIL_SENT));
        assertEmailNotSentTo(emailsSent, "user.email.sent.alreadt@account.gov.uk");
        assertEmailNotSentTo(emailsSent, "user.error.sending@account.gov.uk");
    }

    @Test
    void
            shouldSendCorrectNoOfEmailsForListOfUsersWithVariousStatusAndUpdateStatusWhenSendModeIsNotifyErrors() {
        setupDynamo();
        setupConfig("NOTIFY_ERROR_RETRIES");

        handler.handleRequest(scheduledEvent, context);

        var numberOfUsersWithErrorSendingEmailStatus = 2;
        var numberOfUsersWithEmailAlreadySent = 1;

        var emailsSent =
                notifyStub.waitForNumberOfRequests(60, numberOfUsersWithErrorSendingEmailStatus);

        assertThat(
                bulkEmailUsersService.getNSubjectIdsByStatus(10, BulkEmailStatus.EMAIL_SENT).size(),
                equalTo(
                        numberOfUsersWithErrorSendingEmailStatus
                                + numberOfUsersWithEmailAlreadySent));
        assertThat(emailsSent.size(), equalTo(numberOfUsersWithErrorSendingEmailStatus));
        assertTxmaAuditEventsReceived(
                txmaAuditQueue,
                Collections.nCopies(numberOfUsersWithErrorSendingEmailStatus, BULK_EMAIL_SENT));
    }

    @Test
    void shouldSendCorrectNoOfEmailsWhenSendModeIsDeliveryReceiptRetries() {
        setupConfig("DELIVERY_RECEIPT_TEMPORARY_FAILURE_RETRIES");
        var noOfUsersWithTempFailures = 5;
        IntStream.range(0, noOfUsersWithTempFailures)
                .mapToObj(String::valueOf)
                .forEach(
                        i -> {
                            bulkEmailUsersExtension.addBulkEmailUserWithDeliveryReceiptStatus(
                                    i, "temporary-failure", BulkEmailStatus.EMAIL_SENT);
                            userStore.signUp(
                                    format("user.%s@account.gov.uk", i),
                                    "password123",
                                    new Subject(i),
                                    "1.2");
                        });

        IntStream.range(noOfUsersWithTempFailures, noOfUsersWithTempFailures + 5)
                .mapToObj(String::valueOf)
                .forEach(
                        i -> {
                            bulkEmailUsersExtension.addBulkEmailUserWithDeliveryReceiptStatus(
                                    i, "permanent-failure", BulkEmailStatus.EMAIL_SENT);
                            userStore.signUp(
                                    format("user.%s@account.gov.uk", i),
                                    "password123",
                                    new Subject(i),
                                    "1.2");
                        });

        IntStream.range(10, 15)
                .mapToObj(String::valueOf)
                .forEach(
                        i -> {
                            bulkEmailUsersExtension.addBulkEmailUser(i, BulkEmailStatus.EMAIL_SENT);
                            userStore.signUp(
                                    format("user.%s@account.gov.uk", i),
                                    "password123",
                                    new Subject(i),
                                    "1.2");
                        });

        handler.handleRequest(scheduledEvent, context);

        var emailsSent = notifyStub.waitForNumberOfRequests(20, noOfUsersWithTempFailures);

        var retryEmailSentUsers =
                bulkEmailUsersService.getNSubjectIdsByStatus(100, BulkEmailStatus.RETRY_EMAIL_SENT);

        var RETRY_EMAIL_SENT_USERIDS_SET = Set.of("0", "1", "2", "3", "4");

        assertEquals(noOfUsersWithTempFailures, retryEmailSentUsers.size());
        assertEquals(noOfUsersWithTempFailures, emailsSent.size());
        assertEquals(RETRY_EMAIL_SENT_USERIDS_SET, new HashSet<>(retryEmailSentUsers));
        RETRY_EMAIL_SENT_USERIDS_SET.forEach(
                sub -> {
                    assertEquals(
                            null,
                            bulkEmailUsersService
                                    .getBulkEmailUsers(sub)
                                    .get()
                                    .getDeliveryReceiptStatus());
                });
        assertTxmaAuditEventsReceived(
                txmaAuditQueue, Collections.nCopies(5, BULK_RETRY_EMAIL_SENT));
    }

    @Test
    void shouldSendCorrectNoOfEmailsAndUpdateStatusWhenTwoUsersHaveNoCorrespondingAccount() {
        setupDynamo();
        bulkEmailUsersExtension.addBulkEmailUser("999998", BulkEmailStatus.PENDING);
        bulkEmailUsersExtension.addBulkEmailUser("999999", BulkEmailStatus.PENDING);

        makeRequest();

        var emailsSent = notifyStub.waitForNumberOfRequests(60, 8);

        assertThat(
                bulkEmailUsersService.getNSubjectIdsByStatus(15, BulkEmailStatus.EMAIL_SENT).size(),
                equalTo(9));
        assertThat(
                bulkEmailUsersService
                        .getNSubjectIdsByStatus(15, BulkEmailStatus.ACCOUNT_NOT_FOUND)
                        .size(),
                equalTo(2));
        assertThat(emailsSent.size(), equalTo(8));
        assertEmailNotSentTo(emailsSent, "user.email.sent.already@account.gov.uk");
        assertEmailNotSentTo(emailsSent, "user.error.sending@account.gov.uk");
        assertTxmaAuditEventsReceived(txmaAuditQueue, Collections.nCopies(8, BULK_EMAIL_SENT));
    }

    void assertEmailNotSentTo(List<JsonElement> emailsSent, String email) {
        emailsSent.forEach(
                e -> assertThat(e, hasFieldWithValue("email_address", not(equalTo(email)))));
    }

    private void setupDynamo() {
        bulkEmailUsersExtension.addBulkEmailUser("1", BulkEmailStatus.PENDING);
        bulkEmailUsersExtension.addBulkEmailUser("2", BulkEmailStatus.PENDING);
        bulkEmailUsersExtension.addBulkEmailUser("3", BulkEmailStatus.EMAIL_SENT);
        bulkEmailUsersExtension.addBulkEmailUser("4", BulkEmailStatus.PENDING);
        bulkEmailUsersExtension.addBulkEmailUser("5", BulkEmailStatus.PENDING);
        bulkEmailUsersExtension.addBulkEmailUser("6", BulkEmailStatus.ERROR_SENDING_EMAIL);
        bulkEmailUsersExtension.addBulkEmailUser("7", BulkEmailStatus.PENDING);
        bulkEmailUsersExtension.addBulkEmailUser("8", BulkEmailStatus.PENDING);
        bulkEmailUsersExtension.addBulkEmailUser("9", BulkEmailStatus.PENDING);
        bulkEmailUsersExtension.addBulkEmailUser("10", BulkEmailStatus.PENDING);
        bulkEmailUsersExtension.addBulkEmailUser("11", BulkEmailStatus.PENDING);
        bulkEmailUsersExtension.addBulkEmailUser("12", BulkEmailStatus.PENDING);
        bulkEmailUsersExtension.addBulkEmailUser("13", BulkEmailStatus.ERROR_SENDING_EMAIL);

        userStore.signUp("user.1@account.gov.uk", "password123", new Subject("1"), null);
        userStore.signUp("user.2@account.gov.uk", "password123", new Subject("2"), "1.0");
        userStore.signUp(
                "user.email.sent.already@account.gov.uk", "password123", new Subject("3"), "1.0");
        userStore.signUp("user.4@account.gov.uk", "password123", new Subject("4"), "1.1");
        userStore.signUp("user.5@account.gov.uk", "password123", new Subject("5"), "1.1");
        userStore.signUp(
                "user.error.sending@account.gov.uk", "password123", new Subject("6"), "1.2");
        userStore.signUp("user.7@account.gov.uk", "password123", new Subject("7"), "1.2");
        userStore.signUp("user.8@account.gov.uk", "password123", new Subject("8"), "1.3");
        userStore.signUp("user.9@account.gov.uk", "password123", new Subject("9"), "1.3");
        userStore.signUp("user.10@account.gov.uk", "password123", new Subject("10"), "1.4");
        userStore.signUp("user.11@account.gov.uk", "password123", new Subject("11"), "1.5");
        userStore.signUp("user.12@account.gov.uk", "password123", new Subject("12"), "1.6");
        userStore.signUp("user.13@account.gov.uk", "password123", new Subject("13"), "1.2");
    }

    private ScheduledEvent scheduledEvent =
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

    private void makeRequest() {
        handler.handleRequest(scheduledEvent, context);
    }

    private void setupConfig(String sendMode) {
        var configuration = configWithSendMode(sendMode);
        handler = new BulkUserEmailSenderScheduledEventHandler(configuration);
        bulkEmailUsersService = new BulkEmailUsersService(configuration);
    }

    private static IntegrationTestConfigurationService configWithSendMode(String sendMode) {
        return new IntegrationTestConfigurationService(
                notificationsQueue,
                auditSigningKey,
                tokenSigner,
                ipvPrivateKeyJwtSigner,
                spotQueue,
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
                new SecureRandom().nextBytes(bytes);
                return Hex.encodeHexString(bytes);
            }

            @Override
            public int getBulkUserEmailBatchQueryLimit() {
                return 3;
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
        };
    }
}
