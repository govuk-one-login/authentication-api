package uk.gov.di.authentication.sharedtest.helper;

import com.amazonaws.services.lambda.runtime.events.S3Event;
import com.amazonaws.services.lambda.runtime.events.models.s3.S3EventNotification;

import java.util.ArrayList;
import java.util.Collections;

import static org.mockito.Mockito.mock;

public class S3TestEventHelper {
    private S3TestEventHelper() {}

    public static S3Event generateS3TestEvent(
            String awsRegion, String eventName, String bucketName, String fileName) {
        return new S3Event(
                new ArrayList<>(
                        Collections.singleton(
                                new S3EventNotification.S3EventNotificationRecord(
                                        awsRegion,
                                        eventName,
                                        "aws:s3",
                                        null,
                                        "2.0",
                                        mock(S3EventNotification.RequestParametersEntity.class),
                                        mock(S3EventNotification.ResponseElementsEntity.class),
                                        new S3EventNotification.S3Entity(
                                                "testConfigRule",
                                                new S3EventNotification.S3BucketEntity(
                                                        bucketName,
                                                        mock(
                                                                S3EventNotification
                                                                        .UserIdentityEntity.class),
                                                        ""),
                                                new S3EventNotification.S3ObjectEntity(
                                                        fileName, 1L, "", "", ""),
                                                "1.0"),
                                        mock(S3EventNotification.UserIdentityEntity.class)))));
    }
}
