package uk.gov.di.authentication.audit.lambda;

import com.amazonaws.regions.Regions;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.S3Event;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3Client;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.util.JsonFormat;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.ObjectMessage;
import uk.gov.di.audit.AuditPayload.AuditEvent;
import uk.gov.di.audit.AuditPayload.AuditEvent.User;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.util.Arrays;
import java.util.HashMap;
import java.util.stream.Collectors;

import static org.apache.commons.codec.binary.Hex.encodeHexString;
import static uk.gov.di.authentication.audit.helper.HmacSha256Helper.hmacSha256;

public class CounterFraudAuditReplayLambda implements RequestHandler<S3Event, Void> {

    private static final Logger LOG = LogManager.getLogger(CounterFraudAuditReplayLambda.class);

    private final ConfigurationService configurationService;
    private final String hmacKey;
    private final AmazonS3 client;

    public CounterFraudAuditReplayLambda(
            ConfigurationService configurationService, AmazonS3 client) {
        this.configurationService = configurationService;
        this.hmacKey = configurationService.getAuditHmacSecret();
        this.client = client;
    }

    public CounterFraudAuditReplayLambda() {
        this(
                ConfigurationService.getInstance(),
                AmazonS3Client.builder().withRegion(Regions.EU_WEST_2).build());
    }

    @Override
    public Void handleRequest(S3Event input, Context context) {

        input.getRecords()
                .forEach(
                        s3 -> {
                            var key = s3.getS3().getObject().getKey();
                            var bucket = s3.getS3().getBucket().getName();

                            var content = client.getObjectAsString(bucket, key);
                            var records =
                                    Arrays.stream(content.split("\n")).collect(Collectors.toList());
                            records.forEach(
                                    record -> {
                                        try {
                                            var builder = AuditEvent.newBuilder();
                                            JsonFormat.parser().merge(record, builder);
                                            var auditEvent = builder.build();

                                            handleAuditEvent(auditEvent);
                                        } catch (InvalidProtocolBufferException e) {
                                            LOG.error("Error parsing file content", e);
                                        }
                                    });
                            client.deleteObject(bucket, key);
                        });

        return null;
    }

    void handleAuditEvent(AuditEvent auditEvent) {
        var eventData = new HashMap<String, String>();

        eventData.put("event-id", auditEvent.getEventId());
        eventData.put("request-id", auditEvent.getRequestId());
        eventData.put("session-id", auditEvent.getSessionId());
        eventData.put("client-id", auditEvent.getClientId());
        eventData.put("timestamp", auditEvent.getTimestamp());
        eventData.put("event-name", auditEvent.getEventName());
        eventData.put("persistent-session-id", auditEvent.getPersistentSessionId());

        User user = auditEvent.getUser();

        eventData.put("user.ip-address", user.getIpAddress());

        if (isPresent(user.getId())) {
            eventData.put("user.id", encodeHexString(hmacSha256(user.getId(), hmacKey)));
        }

        if (isPresent(user.getEmail())) {
            eventData.put("user.email", encodeHexString(hmacSha256(user.getEmail(), hmacKey)));
        }

        if (isPresent(user.getPhoneNumber())) {
            eventData.put(
                    "user.phone", encodeHexString(hmacSha256(user.getPhoneNumber(), hmacKey)));
        }

        auditEvent
                .getExtensionsMap()
                .forEach((key, value) -> eventData.put("extensions." + key, value));

        LOG.info(new ObjectMessage(eventData));
    }

    private boolean isPresent(String field) {
        return !(field == null || field.isBlank());
    }
}
