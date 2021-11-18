package uk.gov.di.authentication.queuehandlers;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.frontendapi.services.AwsSqsClient;
import uk.gov.di.authentication.shared.entity.NotifyRequest;
import uk.gov.di.authentication.shared.services.CodeGeneratorService;
import uk.gov.di.authentication.sharedtest.extensions.NotifyStubExtension;

import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.startsWith;
import static uk.gov.di.authentication.shared.entity.NotificationType.ACCOUNT_CREATED_CONFIRMATION;
import static uk.gov.di.authentication.shared.entity.NotificationType.MFA_SMS;
import static uk.gov.di.authentication.shared.entity.NotificationType.RESET_PASSWORD;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_EMAIL;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_PHONE_NUMBER;
import static uk.gov.di.authentication.sharedtest.matchers.JsonMatcher.hasField;
import static uk.gov.di.authentication.sharedtest.matchers.JsonMatcher.hasFieldWithValue;
import static uk.gov.di.authentication.sharedtest.matchers.StringLengthMatcher.withLength;

public class SendNotificationIntegrationTest {

    private static final String TEST_PHONE_NUMBER = "01234567811";
    private static final String TEST_EMAIL_ADDRESS = "joe.bloggs@example.com";
    private static final int VERIFICATION_CODE_LENGTH = 6;

    private static final AwsSqsClient client =
            new AwsSqsClient(
                    "eu-west-2",
                    "http://localhost:45678/123456789012/local-email-notification-queue",
                    Optional.of("http://localhost:45678/"));

    private static final ObjectMapper objectMapper = new ObjectMapper();

    @RegisterExtension
    public static final NotifyStubExtension notifyStub =
            new NotifyStubExtension(19999, objectMapper);

    @BeforeEach
    public void setUp() {
        notifyStub.reset();
        notifyStub.init();
        client.purge();
    }

    @AfterEach
    public void resetStub() {
        notifyStub.reset();
    }

    @Test
    void shouldCallNotifyWhenValidEmailRequestIsAddedToQueue() throws JsonProcessingException {
        client.send(
                objectMapper.writeValueAsString(
                        new NotifyRequest(TEST_EMAIL_ADDRESS, VERIFY_EMAIL, "162534")));

        JsonNode request = notifyStub.waitForRequest(120);
        assertThat(request, hasField("personalisation"));
        JsonNode personalisation = request.get("personalisation");

        assertThat(
                personalisation,
                allOf(
                        hasField("email_address"),
                        hasFieldWithValue("email_address", equalTo(TEST_EMAIL_ADDRESS))));
        assertThat(
                personalisation,
                allOf(
                        hasField("email-address"),
                        hasFieldWithValue("email-address", equalTo(TEST_EMAIL_ADDRESS))));
        assertThat(
                personalisation,
                allOf(
                        hasField("validation-code"),
                        hasFieldWithValue(
                                "validation-code", withLength(equalTo(VERIFICATION_CODE_LENGTH)))));
    }

    @Test
    void shouldCallNotifyWhenValidPhoneNumberRequestIsAddedToQueue()
            throws JsonProcessingException {
        client.send(
                objectMapper.writeValueAsString(
                        new NotifyRequest(TEST_PHONE_NUMBER, VERIFY_PHONE_NUMBER, "162534")));

        JsonNode request = notifyStub.waitForRequest(120);
        assertThat(request, hasField("personalisation"));
        JsonNode personalisation = request.get("personalisation");

        assertThat(
                personalisation,
                allOf(
                        hasField("phone_number"),
                        hasFieldWithValue("phone_number", equalTo(TEST_PHONE_NUMBER))));
        assertThat(
                personalisation,
                allOf(
                        hasField("validation-code"),
                        hasFieldWithValue(
                                "validation-code", withLength(equalTo(VERIFICATION_CODE_LENGTH)))));
    }

    @Test
    void shouldCallNotifyWhenValidMfaRequestIsAddedToQueue() throws JsonProcessingException {
        client.send(
                objectMapper.writeValueAsString(
                        new NotifyRequest(TEST_PHONE_NUMBER, MFA_SMS, "162534")));

        JsonNode request = notifyStub.waitForRequest(120);
        assertThat(request, hasField("personalisation"));
        JsonNode personalisation = request.get("personalisation");
        assertThat(
                personalisation,
                allOf(
                        hasField("phone_number"),
                        hasFieldWithValue("phone_number", equalTo(TEST_PHONE_NUMBER))));
        assertThat(
                personalisation,
                allOf(
                        hasField("validation-code"),
                        hasFieldWithValue(
                                "validation-code", withLength(equalTo(VERIFICATION_CODE_LENGTH)))));
    }

    @Test
    void shouldCallNotifyWhenValidResetPasswordRequestIsAddedToQueue()
            throws JsonProcessingException {
        String code = new CodeGeneratorService().twentyByteEncodedRandomCode();

        client.send(
                objectMapper.writeValueAsString(
                        new NotifyRequest(TEST_EMAIL_ADDRESS, RESET_PASSWORD, code)));

        JsonNode request = notifyStub.waitForRequest(120);
        assertThat(request, hasField("personalisation"));
        JsonNode personalisation = request.get("personalisation");
        assertThat(
                personalisation,
                allOf(
                        hasField("reset-password-link"),
                        hasFieldWithValue("reset-password-link", containsString(code))));
        assertThat(
                personalisation,
                allOf(
                        hasField("reset-password-link"),
                        hasFieldWithValue(
                                "reset-password-link",
                                startsWith("http://localhost:3000/reset-password?code="))));
    }

    @Test
    void shouldCallNotifyWhenValidAccountCreatedRequestIsAddedToQueue()
            throws JsonProcessingException {
        client.send(
                objectMapper.writeValueAsString(
                        new NotifyRequest(TEST_EMAIL_ADDRESS, ACCOUNT_CREATED_CONFIRMATION)));

        JsonNode request = notifyStub.waitForRequest(120);
        assertThat(request, hasField("personalisation"));
        JsonNode personalisation = request.get("personalisation");
        assertThat(
                personalisation,
                allOf(
                        hasField("email_address"),
                        hasFieldWithValue("email_address", equalTo(TEST_EMAIL_ADDRESS))));
        assertThat(
                personalisation,
                allOf(
                        hasField("sign-in-page-url"),
                        hasFieldWithValue("sign-in-page-url", equalTo("http://localhost:3000/"))));
    }
}
