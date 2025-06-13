package uk.gov.di.authentication.testsupport.helpers;

import com.amazonaws.services.lambda.runtime.events.SQSEvent;
import org.apache.commons.codec.digest.DigestUtils;

import java.util.Arrays;
import java.util.Locale;
import java.util.UUID;

public class SqsIntegrationTestHelper {
    private SqsIntegrationTestHelper() {}

    public static <T> SQSEvent createSqsEvent(T... request) {
        var event = new SQSEvent();
        event.setRecords(
                Arrays.stream(request)
                        .map(
                                r -> {
                                    var message = new SQSEvent.SQSMessage();
                                    message.setBody((String) r);
                                    message.setMessageId(UUID.randomUUID().toString());
                                    message.setMd5OfBody(
                                            DigestUtils.md5Hex(message.getBody())
                                                    .toUpperCase(Locale.ROOT));
                                    message.setEventSource("aws:sqs");
                                    message.setAwsRegion("eu-west-2");
                                    message.setEventSourceArn(
                                            "arn:aws:sqs:eu-west-2:123456789012:queue-name");
                                    return message;
                                })
                        .toList());
        return event;
    }
}
