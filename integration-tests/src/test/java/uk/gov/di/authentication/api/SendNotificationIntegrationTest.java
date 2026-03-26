package uk.gov.di.authentication.api;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.frontendapi.entity.SendNotificationRequest;
import uk.gov.di.authentication.frontendapi.lambda.SendNotificationHandler;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.NotificationType;
import uk.gov.di.authentication.shared.helpers.IdGenerator;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;
import uk.gov.di.authentication.sharedtest.extensions.AuthSessionExtension;
import uk.gov.di.authentication.sharedtest.extensions.EmailCheckResultExtension;
import uk.gov.di.authentication.sharedtest.extensions.InternationalSmsSendCountExtension;
import uk.gov.di.authentication.sharedtest.helper.AuditEventExpectation;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper.assertAuditEventExpectations;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.EMAIL;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.INTERNATIONAL_MOBILE_NUMBER;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.UK_MOBILE_NUMBER;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;
import static uk.gov.di.authentication.testsupport.AuditTestConstants.EXTENSIONS_JOURNEY_TYPE;
import static uk.gov.di.authentication.testsupport.AuditTestConstants.EXTENSIONS_MFA_METHOD;
import static uk.gov.di.authentication.testsupport.AuditTestConstants.USER_EMAIL_FIELD;
import static uk.gov.di.authentication.testsupport.AuditTestConstants.USER_PHONE;

class SendNotificationIntegrationTest extends ApiGatewayHandlerIntegrationTest {
    private static final int INTERNATIONAL_SMS_SEND_LIMIT = 3;
    private static final String TEST_REFERENCE = "test-reference";
    private String SESSION_ID;

    @RegisterExtension
    protected static final EmailCheckResultExtension emailCheckResultExtension =
            new EmailCheckResultExtension();

    @RegisterExtension
    protected static final InternationalSmsSendCountExtension internationalSmsSendCountStore =
            new InternationalSmsSendCountExtension(INTERNATIONAL_SMS_SEND_LIMIT);

    private static final AuthSessionExtension authSessionExtension = new AuthSessionExtension();

    private static final ConfigurationService TXMA_WITH_INT_SMS_LIMIT_CONFIG =
            new IntegrationTestConfigurationService(
                    notificationsQueue,
                    tokenSigner,
                    docAppPrivateKeyJwtSigner,
                    configurationParameters) {
                @Override
                public String getTxmaAuditQueueUrl() {
                    return txmaAuditQueue.getQueueUrl();
                }

                @Override
                public int getInternationalSmsNumberSendLimit() {
                    return INTERNATIONAL_SMS_SEND_LIMIT;
                }
            };

    @BeforeEach
    void setup() throws Json.JsonException {
        txmaAuditQueue.clear();
        handler =
                new SendNotificationHandler(
                        TXMA_ENABLED_CONFIGURATION_SERVICE, redisConnectionService);
        SESSION_ID = IdGenerator.generate();
        authSessionExtension.addSession(SESSION_ID);
        authSessionStore.addEmailToSession(SESSION_ID, EMAIL);
    }

    @Test
    void shouldCallSendNotificationEndpointAndPlaceSuccessMessageOnAuditQueueWhenSuccessful() {
        var response =
                makeRequest(
                        Optional.of(
                                new SendNotificationRequest(
                                        EMAIL,
                                        NotificationType.VERIFY_CHANGE_HOW_GET_SECURITY_CODES,
                                        JourneyType.ACCOUNT_RECOVERY)),
                        constructFrontendHeaders(SESSION_ID),
                        Map.of());

        assertThat(response, hasStatus(204));
        var authSession = authSessionExtension.getSession(SESSION_ID).orElseThrow();
        assertThat(
                authSession.getCodeRequestCount(
                        NotificationType.VERIFY_CHANGE_HOW_GET_SECURITY_CODES,
                        JourneyType.ACCOUNT_RECOVERY),
                equalTo(1));

        assertAuditEventExpectations(
                txmaAuditQueue,
                List.of(
                        new AuditEventExpectation(
                                        FrontendAuditableEvent
                                                .AUTH_ACCOUNT_RECOVERY_EMAIL_CODE_SENT)
                                .withAttribute(USER_EMAIL_FIELD, EMAIL)));
    }

    @ParameterizedTest
    @EnumSource(
            value = JourneyType.class,
            names = {"REGISTRATION", "ACCOUNT_RECOVERY"})
    void shouldReturn400WhenInternationalNumberAndFeatureFlagDisabled(JourneyType journeyType)
            throws Json.JsonException {
        handler =
                new SendNotificationHandler(
                        INTERNAL_API_INT_SMS_DISABLED_TXMA_ENABLED_CONFIGUARION_SERVICE,
                        redisConnectionService);

        var requestBody =
                Map.of(
                        "email",
                        EMAIL,
                        "notificationType",
                        NotificationType.VERIFY_PHONE_NUMBER,
                        "phoneNumber",
                        INTERNATIONAL_MOBILE_NUMBER,
                        "journeyType",
                        journeyType);

        var response =
                makeRequest(
                        Optional.of(requestBody), constructFrontendHeaders(SESSION_ID), Map.of());

        assertThat(response, hasStatus(400));
        assertThat(
                response,
                hasBody(
                        objectMapper.writeValueAsString(
                                ErrorResponse.INTERNATIONAL_PHONE_NUMBER_NOT_SUPPORTED)));
    }

    @Test
    void shouldReturn400WhenInternationalNumberHasHitLimit() {
        handler =
                new SendNotificationHandler(TXMA_WITH_INT_SMS_LIMIT_CONFIG, redisConnectionService);

        for (int i = 0; i < INTERNATIONAL_SMS_SEND_LIMIT; i++) {
            internationalSmsSendCountStore.recordSmsSent(
                    INTERNATIONAL_MOBILE_NUMBER, TEST_REFERENCE);
        }

        var requestBody =
                Map.of(
                        "email",
                        EMAIL,
                        "notificationType",
                        NotificationType.VERIFY_PHONE_NUMBER,
                        "phoneNumber",
                        INTERNATIONAL_MOBILE_NUMBER,
                        "journeyType",
                        JourneyType.REGISTRATION);

        var response =
                makeRequest(
                        Optional.of(requestBody), constructFrontendHeaders(SESSION_ID), Map.of());

        assertThat(response, hasStatus(400));
    }

    @Test
    void shouldReturn204WhenInternationalNumberIsBelowLimit() {
        handler =
                new SendNotificationHandler(TXMA_WITH_INT_SMS_LIMIT_CONFIG, redisConnectionService);

        var requestBody =
                Map.of(
                        "email",
                        EMAIL,
                        "notificationType",
                        NotificationType.VERIFY_PHONE_NUMBER,
                        "phoneNumber",
                        INTERNATIONAL_MOBILE_NUMBER,
                        "journeyType",
                        JourneyType.REGISTRATION);

        var response =
                makeRequest(
                        Optional.of(requestBody), constructFrontendHeaders(SESSION_ID), Map.of());

        assertThat(response, hasStatus(204));

        assertAuditEventExpectations(
                txmaAuditQueue,
                List.of(
                        new AuditEventExpectation(FrontendAuditableEvent.AUTH_PHONE_CODE_SENT)
                                .withAttribute(USER_PHONE, INTERNATIONAL_MOBILE_NUMBER)
                                .withAttribute(EXTENSIONS_MFA_METHOD, "default")
                                .withAttribute(EXTENSIONS_JOURNEY_TYPE, "REGISTRATION")));
    }

    @Test
    void shouldReturn204ForDomesticNumberRegardlessOfLimit() {
        handler =
                new SendNotificationHandler(TXMA_WITH_INT_SMS_LIMIT_CONFIG, redisConnectionService);

        var requestBody =
                Map.of(
                        "email",
                        EMAIL,
                        "notificationType",
                        NotificationType.VERIFY_PHONE_NUMBER,
                        "phoneNumber",
                        UK_MOBILE_NUMBER,
                        "journeyType",
                        JourneyType.REGISTRATION);

        var response =
                makeRequest(
                        Optional.of(requestBody), constructFrontendHeaders(SESSION_ID), Map.of());

        assertThat(response, hasStatus(204));

        assertAuditEventExpectations(
                txmaAuditQueue,
                List.of(
                        new AuditEventExpectation(FrontendAuditableEvent.AUTH_PHONE_CODE_SENT)
                                .withAttribute(USER_PHONE, UK_MOBILE_NUMBER)
                                .withAttribute(EXTENSIONS_MFA_METHOD, "default")
                                .withAttribute(EXTENSIONS_JOURNEY_TYPE, "REGISTRATION")));
    }
}
