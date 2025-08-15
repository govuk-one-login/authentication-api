package uk.gov.di.authentication.auditevents.services;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import uk.gov.di.authentication.auditevents.entity.ComponentId;
import uk.gov.di.authentication.auditevents.entity.StructuredAuditEvent;
import uk.gov.di.authentication.shared.helpers.CommonTestVariables;
import uk.gov.di.authentication.shared.services.AwsSqsClient;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.sharedtest.logging.CaptureLoggingExtension;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class StructuredAuditServiceTest {

    @RegisterExtension
    private final CaptureLoggingExtension logging =
            new CaptureLoggingExtension(StructuredAuditService.class);

    @Mock private ConfigurationService configurationService;

    @Mock private AwsSqsClient awsSqsClient;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);

        when(configurationService.getAwsRegion()).thenReturn("eu-west-2");
        when(configurationService.getTxmaAuditQueueUrl())
                .thenReturn("https://queue.amazonaws.com/123456789012/audit-queue");
        when(configurationService.getLocalstackEndpointUri()).thenReturn(Optional.empty());
    }

    @Nested
    class SubmitAuditEvent {

        @Test
        void shouldSubmitAuditEventAsJsonToSqs() {
            TestAuditEvent auditEvent =
                    new TestAuditEvent(
                            "TEST_EVENT",
                            1234567890L,
                            1234567890000L,
                            CommonTestVariables.CLIENT_ID,
                            ComponentId.AUTH.getValue(),
                            new TestAuditEvent.TestUser(
                                    "user-123",
                                    CommonTestVariables.EMAIL,
                                    CommonTestVariables.IP_ADDRESS,
                                    CommonTestVariables.DI_PERSISTENT_SESSION_ID,
                                    CommonTestVariables.CLIENT_SESSION_ID));

            String expectedJson =
                    """
                    {
                      "event_name": "TEST_EVENT",
                      "timestamp": 1234567890,
                      "event_timestamp_ms": 1234567890000,
                      "client_id": "%s",
                      "component_id": "%s",
                      "user": {
                        "user_id": "user-123",
                        "email": "%s",
                        "ip_address": "%s",
                        "persistent_session_id": "%s",
                        "govuk_signin_journey_id": "%s"
                      }
                    }"""
                            .formatted(
                                    CommonTestVariables.CLIENT_ID,
                                    ComponentId.AUTH.getValue(),
                                    CommonTestVariables.EMAIL,
                                    CommonTestVariables.IP_ADDRESS,
                                    CommonTestVariables.DI_PERSISTENT_SESSION_ID,
                                    CommonTestVariables.CLIENT_SESSION_ID)
                            .replaceAll("\\s+", "");

            StructuredAuditService service = new StructuredAuditService(awsSqsClient);

            service.submitAuditEvent(auditEvent);

            verify(awsSqsClient).send(expectedJson);
        }

        @Test
        void shouldLogEventNameWhenSubmittingAuditEvent() {
            TestAuditEvent auditEvent =
                    new TestAuditEvent(
                            "TEST_EVENT",
                            1234567890L,
                            1234567890000L,
                            CommonTestVariables.CLIENT_ID,
                            ComponentId.AUTH.getValue(),
                            new TestAuditEvent.TestUser(
                                    "user-123",
                                    CommonTestVariables.EMAIL,
                                    CommonTestVariables.IP_ADDRESS,
                                    CommonTestVariables.DI_PERSISTENT_SESSION_ID,
                                    CommonTestVariables.CLIENT_SESSION_ID));

            StructuredAuditService service = new StructuredAuditService(awsSqsClient);

            service.submitAuditEvent(auditEvent);

            assertEquals(1, logging.events().size());
            assertTrue(
                    logging.events()
                            .get(0)
                            .getMessage()
                            .getFormattedMessage()
                            .contains("Sending audit event to SQS: TEST_EVENT"));
        }
    }

    @Nested
    class Constants {

        @Test
        void shouldHaveUnknownConstant() {
            assertEquals("", StructuredAuditService.UNKNOWN);
        }
    }

    @Nested
    class Construction {

        @Test
        void shouldCreateServiceWithConfigurationService() {
            StructuredAuditService service = new StructuredAuditService(configurationService);

            assertNotNull(service);
        }

        @Test
        void shouldCreateServiceWithAwsSqsClient() {
            StructuredAuditService service = new StructuredAuditService(awsSqsClient);

            assertNotNull(service);
        }
    }

    private record TestAuditEvent(
            String eventName,
            long timestamp,
            long eventTimestampMs,
            String clientId,
            String componentId,
            TestUser user)
            implements StructuredAuditEvent {

        private record TestUser(
                String userId,
                String email,
                String ipAddress,
                String persistentSessionId,
                String govukSigninJourneyId) {}
    }
}
