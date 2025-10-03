package uk.gov.di.authentication.api;

import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.frontendapi.entity.CheckEmailFraudBlockResponse;
import uk.gov.di.authentication.frontendapi.lambda.CheckEmailFraudBlockHandler;
import uk.gov.di.authentication.shared.domain.AuditableEvent;
import uk.gov.di.authentication.shared.entity.EmailCheckResultStatus;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.helpers.CommonTestVariables;
import uk.gov.di.authentication.shared.helpers.IdGenerator;
import uk.gov.di.authentication.shared.services.DynamoEmailCheckResultService;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;
import uk.gov.di.authentication.sharedtest.extensions.AuthSessionExtension;
import uk.gov.di.authentication.sharedtest.extensions.EmailCheckResultExtension;
import uk.gov.di.authentication.sharedtest.helper.AuditEventExpectation;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_EMAIL_FRAUD_CHECK_BYPASSED;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_EMAIL_FRAUD_CHECK_DECISION_USED;
import static uk.gov.di.authentication.shared.helpers.NowHelper.unixTimePlusNDays;
import static uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper.assertNoTxmaAuditEventsReceived;
import static uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper.assertTxmaAuditEventsReceived;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

public class CheckEmailFraudBlockIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    private static final Subject SUBJECT = new Subject();

    private static final String EXTENSIONS_JOURNEY_TYPE = "extensions.journey_type";
    private static final String EXTENSIONS_COMPONENT_ID = "component_id";

    DynamoEmailCheckResultService dynamoEmailCheckResultService =
            new DynamoEmailCheckResultService(TEST_CONFIGURATION_SERVICE);

    @RegisterExtension
    protected static final EmailCheckResultExtension emailCheckResultExtension =
            new EmailCheckResultExtension();

    @RegisterExtension
    protected static final AuthSessionExtension authSessionExtension = new AuthSessionExtension();

    @BeforeEach
    void setup() {
        handler =
                new CheckEmailFraudBlockHandler(EMAIL_CHECK_AND_TXMA_ENABLED_CONFIGURATION_SERVICE);
        txmaAuditQueue.clear();
    }

    @Nested
    class UserSubmitsEmailForFraudCheck {

        @Test
        void whenNoFraudCheckResultExists() {
            userStore.signUp(CommonTestVariables.EMAIL, "password-1", SUBJECT);
            var sessionId = IdGenerator.generate();
            authSessionExtension.addSession(sessionId);

            Map<String, String> headers =
                    constructFrontendHeaders(sessionId, CommonTestVariables.CLIENT_SESSION_ID);

            var response =
                    makeRequest(
                            Optional.of(format("{ \"email\": \"%s\"}", CommonTestVariables.EMAIL)),
                            headers,
                            Map.of());

            assertThat(response, hasStatus(200));
            assertThat(
                    response,
                    hasJsonBody(
                            new CheckEmailFraudBlockResponse(
                                    CommonTestVariables.EMAIL,
                                    EmailCheckResultStatus.PENDING.getValue())));

            List<AuditableEvent> expectedEvents = List.of(AUTH_EMAIL_FRAUD_CHECK_BYPASSED);
            Map<String, Map<String, String>> eventExpectations = new HashMap<>();

            Map<String, String> fraudCheckBypassedAttributes = new HashMap<>();
            fraudCheckBypassedAttributes.put(
                    EXTENSIONS_JOURNEY_TYPE, JourneyType.REGISTRATION.getValue());
            fraudCheckBypassedAttributes.put(EXTENSIONS_COMPONENT_ID, "AUTH");
            eventExpectations.put(
                    AUTH_EMAIL_FRAUD_CHECK_BYPASSED.name(), fraudCheckBypassedAttributes);

            verifyAuditEvents(expectedEvents, eventExpectations);
        }

        @Test
        void whenEmailIsAllowed() {
            userStore.signUp(CommonTestVariables.EMAIL, "password-1", SUBJECT);
            var sessionId = IdGenerator.generate();
            authSessionExtension.addSession(sessionId);

            dynamoEmailCheckResultService.saveEmailCheckResult(
                    CommonTestVariables.EMAIL,
                    EmailCheckResultStatus.ALLOW,
                    unixTimePlusNDays(1),
                    "test-reference",
                    CommonTestVariables.JOURNEY_ID,
                    CommonTestVariables.EMAIL_CHECK_RESPONSE_TEST_DATA);

            Map<String, String> headers =
                    constructFrontendHeaders(sessionId, CommonTestVariables.CLIENT_SESSION_ID);

            var response =
                    makeRequest(
                            Optional.of(format("{ \"email\": \"%s\"}", CommonTestVariables.EMAIL)),
                            headers,
                            Map.of());

            assertThat(response, hasStatus(200));
            assertThat(
                    response,
                    hasJsonBody(
                            new CheckEmailFraudBlockResponse(
                                    CommonTestVariables.EMAIL,
                                    EmailCheckResultStatus.ALLOW.getValue())));

            List<AuditableEvent> expectedEvents = List.of(AUTH_EMAIL_FRAUD_CHECK_DECISION_USED);
            Map<String, Map<String, String>> eventExpectations = new HashMap<>();
            Map<String, String> fraudCheckDecisionUsedAttributes = new HashMap<>();
            fraudCheckDecisionUsedAttributes.put(
                    EXTENSIONS_JOURNEY_TYPE, JourneyType.REGISTRATION.getValue());
            fraudCheckDecisionUsedAttributes.put(EXTENSIONS_COMPONENT_ID, "AUTH");
            eventExpectations.put(
                    AUTH_EMAIL_FRAUD_CHECK_DECISION_USED.name(), fraudCheckDecisionUsedAttributes);

            verifyAuditEvents(expectedEvents, eventExpectations);
        }

        @Test
        void whenEmailIsDenied() {
            userStore.signUp(CommonTestVariables.EMAIL, "password-1", SUBJECT);
            var sessionId = IdGenerator.generate();
            authSessionExtension.addSession(sessionId);

            dynamoEmailCheckResultService.saveEmailCheckResult(
                    CommonTestVariables.EMAIL,
                    EmailCheckResultStatus.DENY,
                    unixTimePlusNDays(1),
                    "test-reference",
                    CommonTestVariables.JOURNEY_ID,
                    CommonTestVariables.EMAIL_CHECK_RESPONSE_TEST_DATA);

            Map<String, String> headers =
                    constructFrontendHeaders(sessionId, CommonTestVariables.CLIENT_SESSION_ID);

            var response =
                    makeRequest(
                            Optional.of(format("{ \"email\": \"%s\"}", CommonTestVariables.EMAIL)),
                            headers,
                            Map.of());

            assertThat(response, hasStatus(200));
            assertThat(
                    response,
                    hasJsonBody(
                            new CheckEmailFraudBlockResponse(
                                    CommonTestVariables.EMAIL,
                                    EmailCheckResultStatus.DENY.getValue())));

            List<AuditableEvent> expectedEvents = List.of(AUTH_EMAIL_FRAUD_CHECK_DECISION_USED);
            Map<String, Map<String, String>> eventExpectations = new HashMap<>();
            Map<String, String> fraudCheckDecisionUsedAttributes = new HashMap<>();
            fraudCheckDecisionUsedAttributes.put(
                    EXTENSIONS_JOURNEY_TYPE, JourneyType.REGISTRATION.getValue());
            fraudCheckDecisionUsedAttributes.put(EXTENSIONS_COMPONENT_ID, "AUTH");
            eventExpectations.put(
                    AUTH_EMAIL_FRAUD_CHECK_DECISION_USED.name(), fraudCheckDecisionUsedAttributes);

            verifyAuditEvents(expectedEvents, eventExpectations);
        }
    }

    private void verifyAuditEvents(
            List<AuditableEvent> expectedEvents,
            Map<String, Map<String, String>> eventExpectations) {
        List<String> receivedEvents =
                assertTxmaAuditEventsReceived(txmaAuditQueue, expectedEvents, false);

        for (Map.Entry<String, Map<String, String>> eventEntry : eventExpectations.entrySet()) {
            String eventName = eventEntry.getKey();
            Map<String, String> attributes = eventEntry.getValue();

            AuditEventExpectation expectation =
                    new AuditEventExpectation(FrontendAuditableEvent.valueOf(eventName));

            for (Map.Entry<String, String> attributeEntry : attributes.entrySet()) {
                expectation.withAttribute(attributeEntry.getKey(), attributeEntry.getValue());
            }

            expectation.assertPublished(receivedEvents);
            assertNoTxmaAuditEventsReceived(txmaAuditQueue);
        }
    }
}
