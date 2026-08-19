package uk.gov.di.accountmanagement.queuehandlers;

import com.amazonaws.services.lambda.runtime.events.SQSBatchResponse;
import com.amazonaws.services.lambda.runtime.events.SQSEvent;
import com.amazonaws.services.lambda.runtime.events.SQSEvent.SQSMessage;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.RegisterExtension;
import software.amazon.awssdk.services.kms.model.KeyUsageType;
import uk.gov.di.accountmanagement.lambda.InactiveAccountDeletionHandler;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.sharedtest.basetest.HandlerIntegrationTest;
import uk.gov.di.authentication.sharedtest.extensions.KmsKeyExtension;
import uk.org.webcompere.systemstubs.environment.EnvironmentVariables;
import uk.org.webcompere.systemstubs.jupiter.SystemStub;
import uk.org.webcompere.systemstubs.jupiter.SystemStubsExtension;

import java.util.List;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.delete;
import static com.github.tomakehurst.wiremock.client.WireMock.deleteRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathMatching;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static uk.gov.di.accountmanagement.domain.AccountManagementAuditableEvent.AUTH_DELETE_ACCOUNT;
import static uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper.assertTxmaAuditEventsSubmittedWithMatchingNames;

@ExtendWith(SystemStubsExtension.class)
class InactiveAccountDeletionHandlerIntegrationTest
        extends HandlerIntegrationTest<SQSEvent, SQSBatchResponse> {

    private static final String TEST_EMAIL = "inactive-account-test@example.com";
    private static final String TEST_PASSWORD = "password-1";
    private static final String IAD_CLIENT_ID = "inactive-account-deletion-client";
    private static final String INTERNAL_SECTOR_URI = "https://identity.test.account.gov.uk";

    private WireMockServer accountDataApiWireMockServer;
    private String publicSubjectId;

    @SystemStub static EnvironmentVariables environment = new EnvironmentVariables();

    @RegisterExtension
    private static final KmsKeyExtension authToAccountDataSigningKey =
            new KmsKeyExtension("auth-to-account-data-signing-key", KeyUsageType.SIGN_VERIFY);

    @BeforeAll
    static void setupEnvironment() {
        environment.set("AUTH_TO_ACCOUNT_DATA_API_AUDIENCE", "https://example.com/ADAPIAudience");
        environment.set("AUTH_ISSUER_CLAIM", "https://signin.account.gov.uk/");
        environment.set("INACTIVE_ACCOUNT_DELETION_CLIENT_ID", IAD_CLIENT_ID);
        environment.set("AUTH_TO_ACCOUNT_DATA_SIGNING_KEY", authToAccountDataSigningKey.getKeyId());
        environment.set("INTERNAl_SECTOR_URI", INTERNAL_SECTOR_URI);
    }

    @BeforeEach
    void setUp() {
        publicSubjectId = userStore.signUp(TEST_EMAIL, TEST_PASSWORD);
        txmaAuditQueue.clear();

        accountDataApiWireMockServer =
                new WireMockServer(WireMockConfiguration.wireMockConfig().dynamicPort());
        accountDataApiWireMockServer.start();

        var configService =
                createConfigServiceWithAccountDataUri(
                        "http://localhost:" + accountDataApiWireMockServer.port());
        handler = new InactiveAccountDeletionHandler(configService);
    }

    @AfterEach
    void tearDown() {
        if (accountDataApiWireMockServer != null) {
            accountDataApiWireMockServer.stop();
        }
    }

    @Test
    void shouldSuccessfullyDeleteAccountViaDataApi() {
        accountDataApiWireMockServer.stubFor(
                delete(urlPathMatching("/accounts/" + publicSubjectId))
                        .willReturn(aResponse().withStatus(204)));

        var event = createSQSEvent(publicSubjectId);

        SQSBatchResponse response = handler.handleRequest(event, context);

        assertThat(response.getBatchItemFailures(), is(empty()));
        accountDataApiWireMockServer.verify(
                1,
                deleteRequestedFor(urlPathMatching("/accounts/" + publicSubjectId))
                        .withHeader("Authorization", WireMock.matching("Bearer .+")));
        assertTxmaAuditEventsSubmittedWithMatchingNames(
                txmaAuditQueue, List.of(AUTH_DELETE_ACCOUNT));
    }

    @Test
    void shouldReportFailureWhenDataApiReturns404() {
        accountDataApiWireMockServer.stubFor(
                delete(urlPathMatching("/accounts/" + publicSubjectId))
                        .willReturn(aResponse().withStatus(404)));

        var event = createSQSEvent(publicSubjectId);

        SQSBatchResponse response = handler.handleRequest(event, context);

        assertThat(response.getBatchItemFailures(), hasSize(1));
    }

    @Test
    void shouldReportFailureWhenDataApiReturns500() {
        accountDataApiWireMockServer.stubFor(
                delete(urlPathMatching("/accounts/" + publicSubjectId))
                        .willReturn(aResponse().withStatus(500)));

        var event = createSQSEvent(publicSubjectId);

        SQSBatchResponse response = handler.handleRequest(event, context);

        assertThat(response.getBatchItemFailures(), hasSize(1));
    }

    @Test
    void shouldReportFailureForMalformedMessage() {
        var event = createSQSEventWithRawBody("not valid json");

        SQSBatchResponse response = handler.handleRequest(event, context);

        assertThat(response.getBatchItemFailures(), hasSize(1));
        accountDataApiWireMockServer.verify(0, deleteRequestedFor(urlPathMatching("/accounts/.*")));
    }

    @Test
    void shouldReportFailureForMissingPublicSubjectId() {
        var event = createSQSEventWithRawBody("{\"publicSubjectId\": \"\"}");

        SQSBatchResponse response = handler.handleRequest(event, context);

        assertThat(response.getBatchItemFailures(), hasSize(1));
        accountDataApiWireMockServer.verify(0, deleteRequestedFor(urlPathMatching("/accounts/.*")));
    }

    @Test
    void shouldProcessBatchWithMixedSuccessAndFailure() {
        var successPublicSubjectId = userStore.signUp("success-user@example.com", TEST_PASSWORD);
        var failPublicSubjectId = userStore.signUp("fail-user@example.com", TEST_PASSWORD);

        accountDataApiWireMockServer.stubFor(
                delete(urlPathMatching("/accounts/" + successPublicSubjectId))
                        .willReturn(aResponse().withStatus(204)));
        accountDataApiWireMockServer.stubFor(
                delete(urlPathMatching("/accounts/" + failPublicSubjectId))
                        .willReturn(aResponse().withStatus(500)));

        var goodMessage = createSQSMessage("msg-good", successPublicSubjectId);
        var badMessage = createRawSQSMessage("msg-bad", "invalid json");
        var failMessage = createSQSMessage("msg-fail", failPublicSubjectId);

        var event = new SQSEvent();
        event.setRecords(List.of(goodMessage, badMessage, failMessage));

        SQSBatchResponse response = handler.handleRequest(event, context);

        assertThat(response.getBatchItemFailures(), hasSize(2));
        assertEquals("msg-bad", response.getBatchItemFailures().get(0).getItemIdentifier());
        assertEquals("msg-fail", response.getBatchItemFailures().get(1).getItemIdentifier());

        accountDataApiWireMockServer.verify(
                1, deleteRequestedFor(urlPathMatching("/accounts/" + successPublicSubjectId)));
        accountDataApiWireMockServer.verify(
                1, deleteRequestedFor(urlPathMatching("/accounts/" + failPublicSubjectId)));
    }

    private SQSEvent createSQSEvent(String publicSubjectId) {
        String body = "{\"publicSubjectId\": \"" + publicSubjectId + "\"}";
        return createSQSEventWithRawBody(body);
    }

    private SQSEvent createSQSEventWithRawBody(String body) {
        var message = createRawSQSMessage("msg-1", body);
        var event = new SQSEvent();
        event.setRecords(List.of(message));
        return event;
    }

    private SQSMessage createSQSMessage(String messageId, String publicSubjectId) {
        String body = "{\"publicSubjectId\": \"" + publicSubjectId + "\"}";
        return createRawSQSMessage(messageId, body);
    }

    private SQSMessage createRawSQSMessage(String messageId, String body) {
        var message = new SQSMessage();
        message.setMessageId(messageId);
        message.setBody(body);
        return message;
    }

    private ConfigurationService createConfigServiceWithAccountDataUri(String accountDataUri) {
        return new IntegrationTestConfigurationService(
                notificationsQueue, tokenSigner, configurationParameters) {
            @Override
            public String getAccountDataURI() {
                return accountDataUri;
            }

            @Override
            public String getTxmaAuditQueueUrl() {
                return txmaAuditQueue.getQueueUrl();
            }
        };
    }
}
