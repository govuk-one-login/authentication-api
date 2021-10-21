package uk.gov.di.authentication.audit.services;

import com.amazonaws.services.s3.AmazonS3;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class S3ServiceTest {

    @Test
    void shouldPushContentToBucket() {
        var s3Client = mock(AmazonS3.class);

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

        verify(s3Client).putObject("some-bucket", expectedKey, "some-content");
    }
}
