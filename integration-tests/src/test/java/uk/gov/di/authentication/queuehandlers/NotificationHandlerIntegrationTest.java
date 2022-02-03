package uk.gov.di.authentication.queuehandlers;

import com.amazonaws.services.lambda.runtime.Context;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.frontendapi.lambda.NotificationHandler;
import uk.gov.di.authentication.shared.entity.NotifyRequest;
import uk.gov.di.authentication.shared.services.CodeGeneratorService;
import uk.gov.di.authentication.sharedtest.basetest.NotifyIntegrationTest;

import java.security.SecureRandom;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.startsWith;
import static org.mockito.Mockito.mock;
import static uk.gov.di.authentication.shared.entity.NotificationType.ACCOUNT_CREATED_CONFIRMATION;
import static uk.gov.di.authentication.shared.entity.NotificationType.MFA_SMS;
import static uk.gov.di.authentication.shared.entity.NotificationType.RESET_PASSWORD;
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

    @Test
    void shouldCallNotifyWhenValidEmailRequestIsAddedToQueue() throws JsonProcessingException {

        handler.handleRequest(
                createSqsEvent(new NotifyRequest(TEST_EMAIL_ADDRESS, VERIFY_EMAIL, CODE)),
                mock(Context.class));

        JsonNode request = notifyStub.waitForRequest(60);

        assertThat(request, hasFieldWithValue("email_address", equalTo(TEST_EMAIL_ADDRESS)));
        assertThat(request, hasField("personalisation"));

        JsonNode personalisation = request.get("personalisation");
        assertThat(
                personalisation, hasFieldWithValue("email-address", equalTo(TEST_EMAIL_ADDRESS)));
        assertThat(personalisation, hasFieldWithValue("validation-code", equalTo(CODE)));
        assertThat(
                personalisation,
                hasFieldWithValue(
                        "validation-code", withLength(equalTo(VERIFICATION_CODE_LENGTH))));
    }

    @Test
    void shouldCallNotifyWhenValidPhoneNumberRequestIsAddedToQueue()
            throws JsonProcessingException {
        handler.handleRequest(
                createSqsEvent(new NotifyRequest(TEST_PHONE_NUMBER, VERIFY_PHONE_NUMBER, CODE)),
                mock(Context.class));

        JsonNode request = notifyStub.waitForRequest(60);
        assertThat(request, hasFieldWithValue("phone_number", equalTo(TEST_PHONE_NUMBER)));
        assertThat(request, hasField("personalisation"));

        JsonNode personalisation = request.get("personalisation");
        assertThat(personalisation, hasFieldWithValue("validation-code", equalTo(CODE)));
        assertThat(
                personalisation,
                hasFieldWithValue(
                        "validation-code", withLength(equalTo(VERIFICATION_CODE_LENGTH))));
    }

    @Test
    void shouldCallNotifyWhenValidMfaRequestIsAddedToQueue() throws JsonProcessingException {
        handler.handleRequest(
                createSqsEvent(new NotifyRequest(TEST_PHONE_NUMBER, MFA_SMS, CODE)),
                mock(Context.class));

        JsonNode request = notifyStub.waitForRequest(60);
        assertThat(request, hasFieldWithValue("phone_number", equalTo(TEST_PHONE_NUMBER)));
        assertThat(request, hasField("personalisation"));

        JsonNode personalisation = request.get("personalisation");
        assertThat(personalisation, hasFieldWithValue("validation-code", equalTo(CODE)));
        assertThat(
                personalisation,
                hasFieldWithValue(
                        "validation-code", withLength(equalTo(VERIFICATION_CODE_LENGTH))));
    }

    @Test
    void shouldCallNotifyWhenValidResetPasswordRequestIsAddedToQueue()
            throws JsonProcessingException {
        String code = new CodeGeneratorService().twentyByteEncodedRandomCode();
        String resetPasswordLink = "http://localhost:3000/reset-password?code=" + code;

        handler.handleRequest(
                createSqsEvent(
                        new NotifyRequest(TEST_EMAIL_ADDRESS, RESET_PASSWORD, resetPasswordLink)),
                mock(Context.class));

        JsonNode request = notifyStub.waitForRequest(60);

        assertThat(request, hasFieldWithValue("email_address", equalTo(TEST_EMAIL_ADDRESS)));
        assertThat(request, hasField("personalisation"));

        JsonNode personalisation = request.get("personalisation");
        assertThat(
                personalisation,
                hasFieldWithValue("reset-password-link", startsWith(resetPasswordLink)));
        assertThat(personalisation, hasFieldWithValue("reset-password-link", containsString(code)));
    }

    @Test
    void shouldCallNotifyWhenValidAccountCreatedRequestIsAddedToQueue()
            throws JsonProcessingException {
        handler.handleRequest(
                createSqsEvent(new NotifyRequest(TEST_EMAIL_ADDRESS, ACCOUNT_CREATED_CONFIRMATION)),
                mock(Context.class));

        JsonNode request = notifyStub.waitForRequest(60);

        assertThat(request, hasFieldWithValue("email_address", equalTo(TEST_EMAIL_ADDRESS)));
        assertThat(request, hasField("personalisation"));

        JsonNode personalisation = request.get("personalisation");
        assertThat(
                personalisation,
                hasFieldWithValue(
                        "contact-us-link", equalTo("http://localhost:3000/frontend/contact-us")));
    }
}
