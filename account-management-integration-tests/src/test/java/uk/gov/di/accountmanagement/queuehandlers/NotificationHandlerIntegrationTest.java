package uk.gov.di.accountmanagement.queuehandlers;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.SQSEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.http.client.utils.URIBuilder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.accountmanagement.lambda.NotificationHandler;
import uk.gov.di.authentication.shared.entity.NotifyRequest;
import uk.gov.di.authentication.shared.helpers.ObjectMapperFactory;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.sharedtest.extensions.NotifyStubExtension;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Locale;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_EMAIL;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_PHONE_NUMBER;

public class NotificationHandlerIntegrationTest {

    private static final String TEST_PHONE_NUMBER = "01234567811";
    private static final String TEST_EMAIL_ADDRESS = "joe.bloggs@example.com";
    private static final int VERIFICATION_CODE_LENGTH = 6;

    private static final ObjectMapper objectMapper = ObjectMapperFactory.getInstance();

    @RegisterExtension
    public static final NotifyStubExtension notifyStub =
            new NotifyStubExtension(8888, objectMapper);

    private static final ConfigurationService configurationService =
            new TestConfigurationService(notifyStub);
    private static final NotificationHandler handler =
            new NotificationHandler(configurationService);

    @BeforeEach
    public void setUp() {
        notifyStub.init();
    }

    @AfterEach
    public void resetStub() {
        notifyStub.reset();
    }

    @Test
    void shouldCallNotifyWhenValidEmailRequestIsAddedToQueue() throws JsonProcessingException {
        NotifyRequest notifyRequest = new NotifyRequest(TEST_EMAIL_ADDRESS, VERIFY_EMAIL, "162534");

        handler.handleRequest(createSqsEvent(notifyRequest), mock(Context.class));

        JsonNode request = notifyStub.waitForRequest(60);
        JsonNode personalisation = request.get("personalisation");
        assertEquals(TEST_EMAIL_ADDRESS, request.get("email_address").asText());
        assertEquals(TEST_EMAIL_ADDRESS, personalisation.get("email-address").asText());
        assertEquals(
                VERIFICATION_CODE_LENGTH, personalisation.get("validation-code").asText().length());
    }

    @Test
    void shouldCallNotifyWhenValidPhoneNumberRequestIsAddedToQueue()
            throws JsonProcessingException {
        NotifyRequest notifyRequest =
                new NotifyRequest(TEST_PHONE_NUMBER, VERIFY_PHONE_NUMBER, "162534");

        handler.handleRequest(createSqsEvent(notifyRequest), mock(Context.class));

        JsonNode request = notifyStub.waitForRequest(60);
        JsonNode personalisation = request.get("personalisation");
        assertEquals(TEST_PHONE_NUMBER, request.get("phone_number").asText());
        assertEquals(
                VERIFICATION_CODE_LENGTH, personalisation.get("validation-code").asText().length());
    }

    private SQSEvent createSqsEvent(NotifyRequest... notifyRequest) {
        var event = new SQSEvent();
        event.setRecords(
                Arrays.stream(notifyRequest)
                        .map(
                                r -> {
                                    try {
                                        var message = new SQSEvent.SQSMessage();
                                        message.setBody(objectMapper.writeValueAsString(r));
                                        message.setMessageId(UUID.randomUUID().toString());
                                        message.setMd5OfBody(
                                                DigestUtils.md5Hex(message.getBody())
                                                        .toUpperCase(Locale.ROOT));
                                        message.setEventSource("aws:sqs");
                                        message.setAwsRegion("eu-west-2");
                                        message.setEventSourceArn(
                                                "arn:aws:sqs:eu-west-2:123456789012:queue-name");
                                        return message;
                                    } catch (JsonProcessingException e) {
                                        throw new RuntimeException(e);
                                    }
                                })
                        .collect(Collectors.toList()));
        return event;
    }

    private static class TestConfigurationService extends ConfigurationService {

        private final NotifyStubExtension notifyStubExtension;

        public TestConfigurationService(NotifyStubExtension notifyStub) {
            this.notifyStubExtension = notifyStub;
        }

        @Override
        public Optional<String> getNotifyApiUrl() {
            return Optional.of(
                    new URIBuilder()
                            .setHost("localhost")
                            .setPort(notifyStubExtension.getHttpPort())
                            .setScheme("http")
                            .toString());
        }

        @Override
        public String getNotifyApiKey() {
            byte[] bytes = new byte[36];
            new SecureRandom().nextBytes(bytes);
            return Hex.encodeHexString(bytes);
        }
    }
}
