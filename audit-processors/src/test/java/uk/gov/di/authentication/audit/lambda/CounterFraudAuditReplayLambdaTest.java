package uk.gov.di.authentication.audit.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.S3Event;
import com.amazonaws.services.lambda.runtime.events.models.s3.S3EventNotification;
import com.amazonaws.services.s3.AmazonS3;
import org.apache.logging.log4j.core.LogEvent;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.sharedtest.logging.CaptureLoggingExtension;

import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.sharedtest.logging.LogEventMatcher.hasObjectMessageProperty;

class CounterFraudAuditReplayLambdaTest {

    @RegisterExtension
    public final CaptureLoggingExtension logging =
            new CaptureLoggingExtension(CounterFraudAuditReplayLambda.class);

    private final AmazonS3 client = mock(AmazonS3.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);

    @Test
    void shouldDeserialiseAndLogValidRecordsFromS3() {
        final var bucket = "a-bucket";
        final var file = "a-key";
        final var auditRecord =
                "{"
                        + "\"eventId\": \"test-event-id\","
                        + "\"requestId\": \"test-request-id\","
                        + "\"sessionId\": \"test-session-id\","
                        + "\"clientId\": \"test-client-id\","
                        + "\"timestamp\": \"test-timestamp\","
                        + "\"eventName\": \"test-event-name\","
                        + "\"user\": {"
                        + "\"id\": \"test-id\","
                        + "\"email\": \"test-example@digital.cabinet-office.gov.uk\","
                        + "\"phoneNumber\": \"test-phone-number\","
                        + "\"ipAddress\": \"test-ip-address\""
                        + "},"
                        + "\"extensions\": {"
                        + "\"extension-type\": \"test-extension-type\""
                        + "},"
                        + "\"persistentSessionId\": \"test-persistent-session-id\""
                        + "}";

        when(client.getObjectAsString(bucket, file)).thenReturn(auditRecord);
        when(configurationService.getAuditHmacSecret()).thenReturn("i-am-a-fake-hash-key");

        var handler = new CounterFraudAuditReplayLambda(configurationService, client);
        var input = mock(S3Event.class);
        var record = generateEventRecord(bucket, file);
        when(input.getRecords()).thenReturn(List.of(record));
        handler.handleRequest(input, mock(Context.class));

        LogEvent logEvent = logging.events().get(1);

        assertThat(logEvent, hasObjectMessageProperty("event-id", "test-event-id"));
        assertThat(logEvent, hasObjectMessageProperty("request-id", "test-request-id"));
        assertThat(logEvent, hasObjectMessageProperty("session-id", "test-session-id"));
        assertThat(logEvent, hasObjectMessageProperty("client-id", "test-client-id"));
        assertThat(logEvent, hasObjectMessageProperty("timestamp", "test-timestamp"));
        assertThat(logEvent, hasObjectMessageProperty("event-name", "test-event-name"));
        assertThat(
                logEvent,
                hasObjectMessageProperty("persistent-session-id", "test-persistent-session-id"));
        assertThat(
                logEvent,
                hasObjectMessageProperty(
                        "user.email",
                        "dbc2c80d5e663075eb736f52df8446c109878f1a27b9d2f7db634d4e64923c94"));
        assertThat(
                logEvent,
                hasObjectMessageProperty(
                        "user.id",
                        "fe3ad3ffe725ab111628ea3df4b04fb0fda486479fb621c8d4ac325c9e1ce91b"));
        assertThat(
                logEvent,
                hasObjectMessageProperty(
                        "user.phone",
                        "889340bac0d98dc4f74eeef79c907ea763f3915277d641176fa081d8f7b48cd7"));

        assertThat(logEvent, hasObjectMessageProperty("user.ip-address", "test-ip-address"));
        assertThat(
                logEvent,
                hasObjectMessageProperty("extensions.extension-type", "test-extension-type"));

        verify(client).deleteObject(bucket, file);
    }

    @Test
    void shouldDeserialiseAndLogValidRecordsWithMultipleRecordsFromS3() {
        final var bucket = "a-bucket";
        final var file = "a-key";
        final var auditRecords =
                "{"
                        + "\"eventId\": \"test-event-id\","
                        + "\"requestId\": \"test-request-id\","
                        + "\"sessionId\": \"test-session-id\","
                        + "\"clientId\": \"test-client-id\","
                        + "\"timestamp\": \"test-timestamp\","
                        + "\"eventName\": \"test-event-name\","
                        + "\"user\": {"
                        + "\"id\": \"test-id\","
                        + "\"email\": \"test-example@digital.cabinet-office.gov.uk\","
                        + "\"phoneNumber\": \"test-phone-number\","
                        + "\"ipAddress\": \"test-ip-address\""
                        + "},"
                        + "\"extensions\": {"
                        + "\"extension-type\": \"test-extension-value\""
                        + "},"
                        + "\"persistentSessionId\": \"test-persistent-session-id\""
                        + "}\n"
                        + "{"
                        + "\"eventId\": \"a-second-test-event-id\","
                        + "\"requestId\": \"a-second-test-request-id\","
                        + "\"sessionId\": \"a-second-test-session-id\","
                        + "\"clientId\": \"a-second-test-client-id\","
                        + "\"timestamp\": \"a-second-test-timestamp\","
                        + "\"eventName\": \"a-second-test-event-name\","
                        + "\"user\": {"
                        + "\"id\": \"a-second-test-id\","
                        + "\"email\": \"a-second-test-example@digital.cabinet-office.gov.uk\","
                        + "\"phoneNumber\": \"a-second-test-phone-number\","
                        + "\"ipAddress\": \"a-second-test-ip-address\""
                        + "},"
                        + "\"extensions\": {"
                        + "\"a-second-extension-type\": \"a-second-test-extension-value\""
                        + "},"
                        + "\"persistentSessionId\": \"a-second-test-persistent-session-id\""
                        + "}";

        when(client.getObjectAsString(bucket, file)).thenReturn(auditRecords);
        when(configurationService.getAuditHmacSecret()).thenReturn("i-am-a-fake-hash-key");

        var handler = new CounterFraudAuditReplayLambda(configurationService, client);
        var input = mock(S3Event.class);
        var record = generateEventRecord(bucket, file);
        when(input.getRecords()).thenReturn(List.of(record));
        handler.handleRequest(input, mock(Context.class));

        LogEvent logEvent = logging.events().get(1);

        assertThat(logEvent, hasObjectMessageProperty("event-id", "test-event-id"));
        assertThat(logEvent, hasObjectMessageProperty("request-id", "test-request-id"));
        assertThat(logEvent, hasObjectMessageProperty("session-id", "test-session-id"));
        assertThat(logEvent, hasObjectMessageProperty("client-id", "test-client-id"));
        assertThat(logEvent, hasObjectMessageProperty("timestamp", "test-timestamp"));
        assertThat(logEvent, hasObjectMessageProperty("event-name", "test-event-name"));
        assertThat(
                logEvent,
                hasObjectMessageProperty("persistent-session-id", "test-persistent-session-id"));
        assertThat(
                logEvent,
                hasObjectMessageProperty(
                        "user.email",
                        "dbc2c80d5e663075eb736f52df8446c109878f1a27b9d2f7db634d4e64923c94"));
        assertThat(
                logEvent,
                hasObjectMessageProperty(
                        "user.id",
                        "fe3ad3ffe725ab111628ea3df4b04fb0fda486479fb621c8d4ac325c9e1ce91b"));
        assertThat(
                logEvent,
                hasObjectMessageProperty(
                        "user.phone",
                        "889340bac0d98dc4f74eeef79c907ea763f3915277d641176fa081d8f7b48cd7"));

        assertThat(logEvent, hasObjectMessageProperty("user.ip-address", "test-ip-address"));
        assertThat(
                logEvent,
                hasObjectMessageProperty("extensions.extension-type", "test-extension-value"));

        logEvent = logging.events().get(2);

        assertThat(logEvent, hasObjectMessageProperty("event-id", "a-second-test-event-id"));
        assertThat(logEvent, hasObjectMessageProperty("request-id", "a-second-test-request-id"));
        assertThat(logEvent, hasObjectMessageProperty("session-id", "a-second-test-session-id"));
        assertThat(logEvent, hasObjectMessageProperty("client-id", "a-second-test-client-id"));
        assertThat(logEvent, hasObjectMessageProperty("timestamp", "a-second-test-timestamp"));
        assertThat(logEvent, hasObjectMessageProperty("event-name", "a-second-test-event-name"));
        assertThat(
                logEvent,
                hasObjectMessageProperty(
                        "persistent-session-id", "a-second-test-persistent-session-id"));

        assertThat(
                logEvent, hasObjectMessageProperty("user.ip-address", "a-second-test-ip-address"));
        assertThat(
                logEvent,
                hasObjectMessageProperty(
                        "extensions.a-second-extension-type", "a-second-test-extension-value"));

        verify(client).deleteObject(bucket, file);
    }

    private S3EventNotification.S3EventNotificationRecord generateEventRecord(
            String bucketName, String key) {
        var eventRecord = mock(S3EventNotification.S3EventNotificationRecord.class);
        var s3 = mock(S3EventNotification.S3Entity.class);
        var bucket = mock(S3EventNotification.S3BucketEntity.class);
        var file = mock(S3EventNotification.S3ObjectEntity.class);
        when(file.getKey()).thenReturn(key);
        when(bucket.getName()).thenReturn(bucketName);
        when(s3.getBucket()).thenReturn(bucket);
        when(s3.getObject()).thenReturn(file);
        when(eventRecord.getS3()).thenReturn(s3);

        return eventRecord;
    }
}
