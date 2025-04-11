package uk.gov.di.authentication.queuehandlers;

import com.amazonaws.services.lambda.runtime.Context;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.authentication.frontendapi.lambda.NotificationHandler;
import uk.gov.di.authentication.shared.entity.NotificationType;
import uk.gov.di.authentication.shared.entity.NotifyRequest;
import uk.gov.di.authentication.shared.helpers.LocaleHelper.SupportedLanguage;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.sharedtest.basetest.NotifyIntegrationTest;

import java.security.SecureRandom;
import java.util.stream.Stream;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.Mockito.mock;
import static uk.gov.di.authentication.shared.entity.NotificationType.ACCOUNT_CREATED_CONFIRMATION;
import static uk.gov.di.authentication.shared.entity.NotificationType.CHANGE_HOW_GET_SECURITY_CODES_CONFIRMATION;
import static uk.gov.di.authentication.shared.entity.NotificationType.MFA_SMS;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_EMAIL;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_PHONE_NUMBER;
import static uk.gov.di.authentication.sharedtest.matchers.JsonMatcher.hasField;
import static uk.gov.di.authentication.sharedtest.matchers.JsonMatcher.hasFieldWithValue;
import static uk.gov.di.authentication.sharedtest.matchers.StringLengthMatcher.withLength;

public class NotificationHandlerIntegrationTest extends NotifyIntegrationTest {

    private static final String TEST_PHONE_NUMBER = "01234567811";
    private static final String TEST_EMAIL_ADDRESS = "joe.bloggs@example.com";
    private static final int VERIFICATION_CODE_LENGTH = 6;

    private final NotificationHandler handler = new NotificationHandler(configurationService);
    public final String CODE = format("%06d", new SecureRandom().nextInt(999999));
    public static final String SESSION_ID = "session-id";
    public static final String CLIENT_SESSION_ID = "known-client-session-id";

    @Test
    void shouldCallNotifyWhenValidEmailRequestIsAddedToQueue() throws Json.JsonException {

        handler.handleRequest(
                createSqsEvent(
                        new NotifyRequest(
                                TEST_EMAIL_ADDRESS,
                                VERIFY_EMAIL,
                                CODE,
                                SupportedLanguage.EN,
                                SESSION_ID,
                                CLIENT_SESSION_ID)),
                mock(Context.class));

        var request = notifyStub.waitForRequest(60);

        assertThat(request, hasFieldWithValue("email_address", equalTo(TEST_EMAIL_ADDRESS)));
        assertThat(request, hasField("personalisation"));

        var personalisation = request.getAsJsonObject().get("personalisation");
        assertThat(
                personalisation, hasFieldWithValue("email-address", equalTo(TEST_EMAIL_ADDRESS)));
        assertThat(personalisation, hasFieldWithValue("validation-code", equalTo(CODE)));
        assertThat(
                personalisation,
                hasFieldWithValue(
                        "validation-code", withLength(equalTo(VERIFICATION_CODE_LENGTH))));
    }

    @Test
    void shouldCallNotifyWhenValidPhoneNumberRequestIsAddedToQueue() throws Json.JsonException {
        handler.handleRequest(
                createSqsEvent(
                        new NotifyRequest(
                                TEST_PHONE_NUMBER,
                                VERIFY_PHONE_NUMBER,
                                CODE,
                                SupportedLanguage.EN,
                                SESSION_ID,
                                CLIENT_SESSION_ID)),
                mock(Context.class));

        var request = notifyStub.waitForRequest(60);
        assertThat(request, hasFieldWithValue("phone_number", equalTo(TEST_PHONE_NUMBER)));
        assertThat(request, hasField("personalisation"));

        var personalisation = request.getAsJsonObject().get("personalisation");
        assertThat(personalisation, hasFieldWithValue("validation-code", equalTo(CODE)));
        assertThat(
                personalisation,
                hasFieldWithValue(
                        "validation-code", withLength(equalTo(VERIFICATION_CODE_LENGTH))));
    }

    @Test
    void shouldCallNotifyWhenValidMfaRequestIsAddedToQueue() throws Json.JsonException {
        handler.handleRequest(
                createSqsEvent(
                        new NotifyRequest(
                                TEST_PHONE_NUMBER,
                                MFA_SMS,
                                CODE,
                                SupportedLanguage.EN,
                                SESSION_ID,
                                CLIENT_SESSION_ID)),
                mock(Context.class));

        var request = notifyStub.waitForRequest(60);
        assertThat(request, hasFieldWithValue("phone_number", equalTo(TEST_PHONE_NUMBER)));
        assertThat(request, hasField("personalisation"));

        var personalisation = request.getAsJsonObject().get("personalisation");
        assertThat(personalisation, hasFieldWithValue("validation-code", equalTo(CODE)));
        assertThat(
                personalisation,
                hasFieldWithValue(
                        "validation-code", withLength(equalTo(VERIFICATION_CODE_LENGTH))));
    }

    private static Stream<Arguments> confirmationEmails() {
        return Stream.of(
                Arguments.of(ACCOUNT_CREATED_CONFIRMATION, "accountCreatedEmail"),
                Arguments.of(
                        CHANGE_HOW_GET_SECURITY_CODES_CONFIRMATION, "changeCodesConfirmEmail"));
    }

    @ParameterizedTest
    @MethodSource("confirmationEmails")
    void shouldCallNotifyWhenValidAccountCreatedRequestIsAddedToQueue(
            NotificationType notificationType) throws Json.JsonException {
        handler.handleRequest(
                createSqsEvent(
                        new NotifyRequest(
                                TEST_EMAIL_ADDRESS,
                                notificationType,
                                SupportedLanguage.EN,
                                SESSION_ID,
                                CLIENT_SESSION_ID)),
                mock(Context.class));

        var request = notifyStub.waitForRequest(60);

        assertThat(request, hasFieldWithValue("email_address", equalTo(TEST_EMAIL_ADDRESS)));
        assertThat(request, hasField("personalisation"));

        var personalisation = request.getAsJsonObject().get("personalisation");
        assertThat(
                personalisation,
                hasFieldWithValue(
                        "contact-us-link",
                        equalTo("http://localhost:3000/frontend/contact-gov-uk-one-login")));
    }
}
