package uk.gov.di.authentication.audit.services;

import org.junit.jupiter.api.Test;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class S3ServiceTest {

    @Test
    void shouldPushContentToBucket() {
        var s3Client = mock(S3Client.class);

        var service =
                new S3Service(
                        s3Client,
                        "some-bucket",
                        Clock.fixed(Instant.ofEpochSecond(0), ZoneId.of("UTC")));

        service.storeRecords("some-content");

        var expectedKey =
                "1970/01/01/audit-000000-"
                        + "0a8cac771ca188eacc57e2c96c31f5611925c5ecedccb16b8c236d6c0d325112" // content hash
                        + ".json";

        var putObjectRequest =
                PutObjectRequest.builder().bucket("some-bucket").key(expectedKey).build();

        verify(s3Client).putObject(eq(putObjectRequest), any(RequestBody.class));
    }
}
