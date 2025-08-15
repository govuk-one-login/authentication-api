package uk.gov.di.authentication.services;

import com.google.gson.annotations.SerializedName;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.auditevents.entity.ComponentId;
import uk.gov.di.authentication.auditevents.services.StructuredAuditService;
import uk.gov.di.authentication.shared.helpers.CommonTestVariables;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.sharedtest.extensions.SqsQueueExtension;

import java.util.List;

import static org.awaitility.Awaitility.await;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class StructuredAuditServiceIntegrationTest {

    @RegisterExtension
    protected static final SqsQueueExtension sqsQueue = new SqsQueueExtension("local-audit-queue");

    private StructuredAuditService structuredAuditService;

    @BeforeEach
    void setUp() {
        ConfigurationService configurationService = new TestConfigurationService();
        structuredAuditService = new StructuredAuditService(configurationService);
    }

    @Test
    void shouldSuccessfullySubmitStructuredAuditEventToQueue() {
        TestAuditEvent auditEvent =
                new TestAuditEvent(
                        "TEST_EVENT",
                        System.currentTimeMillis() / 1000,
                        System.currentTimeMillis(),
                        CommonTestVariables.CLIENT_ID,
                        ComponentId.AUTH.getValue(),
                        new TestAuditEvent.TestUser(
                                "test-user-id",
                                CommonTestVariables.EMAIL,
                                CommonTestVariables.IP_ADDRESS,
                                CommonTestVariables.DI_PERSISTENT_SESSION_ID,
                                CommonTestVariables.CLIENT_SESSION_ID),
                        new TestAuditEvent.TestExtensions("REGISTRATION", "testValue"));

        assertDoesNotThrow(() -> structuredAuditService.submitAuditEvent(auditEvent));

        await().untilAsserted(
                        () -> {
                            List<String> messages = sqsQueue.getRawMessages();
                            assertEquals(1, messages.size());

                            String message = messages.get(0);
                            assertTrue(message.contains("TEST_EVENT"));
                            assertTrue(message.contains(CommonTestVariables.EMAIL));
                            assertTrue(message.contains(CommonTestVariables.CLIENT_ID));
                            assertTrue(message.contains("REGISTRATION"));
                        });
    }

    @Test
    void shouldSerializeEventWithCorrectSnakeCaseProperties() {
        TestAuditEvent auditEvent =
                new TestAuditEvent(
                        "TEST_EVENT",
                        System.currentTimeMillis() / 1000,
                        System.currentTimeMillis(),
                        CommonTestVariables.CLIENT_ID,
                        ComponentId.AUTH.getValue(),
                        new TestAuditEvent.TestUser(
                                "test-user-id",
                                CommonTestVariables.EMAIL,
                                CommonTestVariables.IP_ADDRESS,
                                CommonTestVariables.DI_PERSISTENT_SESSION_ID,
                                CommonTestVariables.CLIENT_SESSION_ID),
                        new TestAuditEvent.TestExtensions("REGISTRATION", "testValue"));

        assertDoesNotThrow(() -> structuredAuditService.submitAuditEvent(auditEvent));

        await().untilAsserted(
                        () -> {
                            List<String> messages = sqsQueue.getRawMessages();
                            assertEquals(1, messages.size());

                            String message = messages.get(0);

                            assertTrue(message.contains("\"event_name\":"));
                            assertTrue(message.contains("\"event_timestamp_ms\":"));
                            assertTrue(message.contains("\"client_id\":"));
                            assertTrue(message.contains("\"component_id\":"));
                            assertTrue(message.contains("\"user_id\":"));
                            assertTrue(message.contains("\"ip_address\":"));
                            assertTrue(message.contains("\"persistent_session_id\":"));
                            assertTrue(message.contains("\"govuk_signin_journey_id\":"));
                            assertTrue(message.contains("\"journey_type\":"));

                            assertTrue(message.contains("\"exampleCamelCaseName\":"));
                        });
    }

    @Test
    void shouldHandleMultipleAuditEvents() {
        String[] journeyTypes = {"REGISTRATION", "SIGN_IN", "ACCOUNT_RECOVERY"};

        for (String journeyType : journeyTypes) {
            TestAuditEvent auditEvent =
                    new TestAuditEvent(
                            "TEST_EVENT",
                            System.currentTimeMillis() / 1000,
                            System.currentTimeMillis(),
                            CommonTestVariables.CLIENT_ID,
                            ComponentId.AUTH.getValue(),
                            new TestAuditEvent.TestUser(
                                    "test-user-id",
                                    CommonTestVariables.EMAIL,
                                    CommonTestVariables.IP_ADDRESS,
                                    CommonTestVariables.DI_PERSISTENT_SESSION_ID,
                                    CommonTestVariables.CLIENT_SESSION_ID),
                            new TestAuditEvent.TestExtensions(journeyType, "testValue"));

            assertDoesNotThrow(() -> structuredAuditService.submitAuditEvent(auditEvent));
        }

        await().untilAsserted(
                        () -> {
                            List<String> messages = sqsQueue.getRawMessages();
                            assertEquals(3, messages.size());

                            assertTrue(messages.stream().anyMatch(m -> m.contains("REGISTRATION")));
                            assertTrue(messages.stream().anyMatch(m -> m.contains("SIGN_IN")));
                            assertTrue(
                                    messages.stream()
                                            .anyMatch(m -> m.contains("ACCOUNT_RECOVERY")));
                        });
    }

    private record TestAuditEvent(
            String eventName,
            long timestamp,
            long eventTimestampMs,
            String clientId,
            String componentId,
            TestUser user,
            TestExtensions extensions)
            implements uk.gov.di.authentication.auditevents.entity.StructuredAuditEvent {

        private record TestUser(
                String userId,
                String email,
                String ipAddress,
                String persistentSessionId,
                String govukSigninJourneyId) {}

        private record TestExtensions(
                String journeyType,
                @SerializedName("exampleCamelCaseName") String exampleCamelCaseName) {}
    }

    private static class TestConfigurationService extends ConfigurationService {
        @Override
        public String getAwsRegion() {
            return "eu-west-2";
        }

        @Override
        public String getTxmaAuditQueueUrl() {
            return sqsQueue.getQueueUrl();
        }
    }
}
