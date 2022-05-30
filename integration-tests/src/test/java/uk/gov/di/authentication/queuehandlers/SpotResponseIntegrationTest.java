package uk.gov.di.authentication.queuehandlers;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.SQSEvent;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.apache.commons.codec.digest.DigestUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.ipv.entity.SPOTResponse;
import uk.gov.di.authentication.ipv.entity.SPOTStatus;
import uk.gov.di.authentication.ipv.lambda.SPOTResponseHandler;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.sharedtest.basetest.HandlerIntegrationTest;

import java.util.Arrays;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

public class SpotResponseIntegrationTest extends HandlerIntegrationTest<SQSEvent, Object> {

    @BeforeEach
    void setup() {
        handler = new SPOTResponseHandler(TEST_CONFIGURATION_SERVICE);
    }

    @Test
    void shouldAddSpotCredentialToDBForValidResponse() {
        var signedCredential = "some-signed-credential";
        var pairwiseIdentifier = new Subject();
        handler.handleRequest(
                createSqsEvent(
                        new SPOTResponse(
                                Map.of(
                                        "https://vocab.sign-in.service.gov.uk/v1/verifiableIdentityJWT",
                                        signedCredential),
                                pairwiseIdentifier.getValue(),
                                SPOTStatus.ACCEPTED)),
                mock(Context.class));

        assertTrue(identityStore.getIdentityCredentials(pairwiseIdentifier.getValue()).isPresent());

        assertThat(
                identityStore
                        .getIdentityCredentials(pairwiseIdentifier.getValue())
                        .get()
                        .getCoreIdentityJWT(),
                equalTo(signedCredential));
    }

    private <T> SQSEvent createSqsEvent(T... request) {
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
}
