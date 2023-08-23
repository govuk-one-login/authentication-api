package uk.gov.di.authentication.utils;

import com.amazonaws.services.lambda.runtime.events.ScheduledEvent;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.joda.time.DateTime;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.shared.entity.BulkEmailStatus;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.BulkEmailUsersService;
import uk.gov.di.authentication.shared.services.LambdaInvokerService;
import uk.gov.di.authentication.sharedtest.basetest.HandlerIntegrationTest;
import uk.gov.di.authentication.sharedtest.extensions.BulkEmailUsersExtension;
import uk.gov.di.authentication.utils.lambda.BulkUserEmailAudienceLoaderScheduledEventHandler;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static java.lang.String.format;
import static java.lang.String.valueOf;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertTrue;

class BulkUserEmailAudienceLoaderScheduledEventHandlerIntegrationTest
        extends HandlerIntegrationTest<ScheduledEvent, Void> {

    @RegisterExtension
    protected static final BulkEmailUsersExtension bulkEmailUsersExtension =
            new BulkEmailUsersExtension();

    private BulkEmailUsersService bulkEmailUsersService;

    private Long bulkUserEmailAudienceLoadUserBatchSize = 5L;

    private Long bulkUserEmailMaxAudienceLoadUserCount = 24L;

    @BeforeEach
    void setup() {
        var configuration =
                new IntegrationTestConfigurationService(
                        auditTopic,
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
                    public int getBulkUserEmailBatchQueryLimit() {
                        return 3;
                    }

                    @Override
                    public long getBulkUserEmailAudienceLoadUserBatchSize() {
                        return bulkUserEmailAudienceLoadUserBatchSize;
                    }

                    @Override
                    public long getBulkUserEmailMaxAudienceLoadUserCount() {
                        return bulkUserEmailMaxAudienceLoadUserCount;
                    }

                    @Override
                    public boolean isBulkUserEmailEmailSendingEnabled() {
                        return true;
                    }
                };

        handler = new BulkUserEmailAudienceLoaderScheduledEventHandler(configuration);
        var lambdaInvokerService =
                new LambdaInvokerService(configuration, null) {
                    @Override
                    public void invokeWithPayload(ScheduledEvent scheduledEvent) {
                        handler.handleRequest(scheduledEvent, context);
                    }
                };

        ((BulkUserEmailAudienceLoaderScheduledEventHandler) handler)
                .setLambdaInvoker(lambdaInvokerService);

        bulkEmailUsersService = new BulkEmailUsersService(configuration);
    }

    @Test
    void shouldLoadSingleUserFromUserProfile() throws Json.JsonException {

        userStore.signUp("user.1@account.gov.uk", "password123", new Subject("1"));

        makeRequest(Optional.empty());

        var usersLoaded = bulkEmailUsersService.getNSubjectIdsByStatus(10, BulkEmailStatus.PENDING);

        assertThat(usersLoaded.get(0), equalTo("1"));
        assertThat(usersLoaded.size(), equalTo(1));
    }

    @Test
    void shouldLoadMultipleUsersFromUserProfileWhenBatchSizeLowerThanUsers() {
        final int numberOfUsers = bulkUserEmailAudienceLoadUserBatchSize.intValue() + 10;
        setupDynamo(numberOfUsers);
        makeRequest(Optional.empty());

        var usersLoaded =
                bulkEmailUsersService.getNSubjectIdsByStatus(
                        numberOfUsers + 1, BulkEmailStatus.PENDING);

        assertThat(usersLoaded.size(), equalTo(numberOfUsers));
        for (int i = 1; i <= usersLoaded.size(); i++) {
            assertTrue(usersLoaded.contains(valueOf(i)));
        }
    }

    @Test
    void shouldLoadMultipleUsersFromUserProfileWhenBatchSizeHigherThanUsers() {
        final int numberOfUsers = 7;
        setupDynamo(numberOfUsers);
        makeRequest(Optional.empty());

        var usersLoaded =
                bulkEmailUsersService.getNSubjectIdsByStatus(
                        numberOfUsers + 1, BulkEmailStatus.PENDING);

        assertThat(usersLoaded.size(), equalTo(numberOfUsers));
        for (int i = 1; i <= usersLoaded.size(); i++) {
            assertTrue(usersLoaded.contains(valueOf(i)));
        }
    }

    private void setupDynamo(int numberOfUsers) {
        for (int i = 1; i <= numberOfUsers; i++) {
            userStore.signUp(
                    format("user.%o@account.gov.uk", i), "password123", new Subject(valueOf(i)));
        }
    }

    private void makeRequest(Optional<Map<String, Object>> exclusiveStartKey) {
        var detail = exclusiveStartKey.orElse(Map.of());
        ScheduledEvent scheduledEvent =
                new ScheduledEvent()
                        .withAccount("12345678")
                        .withRegion("eu-west-2")
                        .withDetailType("Scheduled Event")
                        .withDetail(detail)
                        .withSource("aws.events")
                        .withId("abcd-1234-defg-5678")
                        .withTime(DateTime.now())
                        .withResources(
                                List.of(
                                        "arn:aws:events:eu-west-2:12345678:rule/email-campaign-audience-load-rule"));

        handler.handleRequest(scheduledEvent, context);
    }
}
