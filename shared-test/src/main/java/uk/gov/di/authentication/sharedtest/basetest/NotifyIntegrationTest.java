package uk.gov.di.authentication.sharedtest.basetest;

import com.amazonaws.services.lambda.runtime.events.SQSEvent;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.http.client.utils.URIBuilder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SerializationService;
import uk.gov.di.authentication.sharedtest.extensions.NotifyStubExtension;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Locale;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

public abstract class NotifyIntegrationTest {
    protected static final Json objectMapper = SerializationService.getInstance();

    @RegisterExtension
    public static final NotifyStubExtension notifyStub = new NotifyStubExtension(objectMapper);

    protected static final ConfigurationService configurationService =
            new TestConfigurationService(notifyStub);

    @BeforeEach
    void setUp() {
        notifyStub.init();
    }

    @AfterEach
    void resetStub() {
        notifyStub.reset();
    }

    protected <T> SQSEvent createSqsEvent(T... request) {
        var event = new SQSEvent();
        event.setRecords(
                Arrays.stream(request)
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
                                    } catch (Json.JsonException e) {
                                        throw new RuntimeException(e);
                                    }
                                })
                        .collect(Collectors.toList()));
        return event;
    }

    protected static class TestConfigurationService extends ConfigurationService {

        private final NotifyStubExtension notifyStubExtension;
        private final String notifyApiKey;

        public TestConfigurationService(NotifyStubExtension notifyStub) {
            this.notifyStubExtension = notifyStub;
            byte[] bytes = new byte[36];
            new SecureRandom().nextBytes(bytes);
            this.notifyApiKey = Hex.encodeHexString(bytes);
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
            return notifyApiKey;
        }

        @Override
        public String getAccountManagementURI() {
            return "http://localhost:3000/";
        }

        @Override
        public String getFrontendBaseUrl() {
            return "http://localhost:3000/frontend/";
        }

        @Override
        public String getContactUsLinkRoute() {
            return "contact-us";
        }
    }
}
