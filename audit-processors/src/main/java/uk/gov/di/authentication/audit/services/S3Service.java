package uk.gov.di.authentication.audit.services;

import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.net.URI;
import java.time.Clock;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

import static uk.gov.di.authentication.shared.helpers.HashHelper.hashSha256String;

public class S3Service {
    private static final DateTimeFormatter FORMATTER =
            DateTimeFormatter.ofPattern("yyyy/MM/dd/'audit'-HHmmss").withZone(ZoneId.of("UTC"));

    private final String bucket;
    private final S3Client s3Client;
    private final Clock clock;

    public S3Service(ConfigurationService configService) {
        this.bucket = configService.getAuditStorageS3Bucket();
        var awsRegion = configService.getAwsRegion();
        this.s3Client =
                configService
                        .getLocalstackEndpointUri()
                        .map(
                                endpoint ->
                                        S3Client.builder()
                                                .endpointOverride(URI.create(endpoint))
                                                .region(Region.of(awsRegion)))
                        .orElse(S3Client.builder().region(Region.of(awsRegion)))
                        .build();

        this.clock = Clock.systemUTC();
    }

    protected S3Service(S3Client s3Client, String bucket, Clock clock) {
        this.s3Client = s3Client;
        this.bucket = bucket;
        this.clock = clock;
    }

    public void storeRecords(String payloads) {
        var key = FORMATTER.format(clock.instant()) + "-" + hashSha256String(payloads) + ".json";
        var putObjectRequest = PutObjectRequest.builder().bucket(bucket).key(key).build();
        s3Client.putObject(putObjectRequest, RequestBody.fromString(payloads));
    }
}
