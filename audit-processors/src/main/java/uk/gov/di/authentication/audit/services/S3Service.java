package uk.gov.di.authentication.audit.services;

import com.amazonaws.client.builder.AwsClientBuilder.EndpointConfiguration;
import com.amazonaws.services.s3.AmazonS3;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.time.Clock;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

import static com.amazonaws.services.s3.AmazonS3ClientBuilder.standard;
import static uk.gov.di.authentication.shared.helpers.HashHelper.hashSha256String;

public class S3Service {
    private static final DateTimeFormatter FORMATTER =
            DateTimeFormatter.ofPattern("yyyy/MM/dd/'audit'-HHmmss").withZone(ZoneId.of("UTC"));

    private final String bucket;
    private final AmazonS3 s3Client;
    private final Clock clock;

    public S3Service(ConfigurationService configService) {
        this.bucket = configService.getAuditStorageS3Bucket();
        var awsRegion = configService.getAwsRegion();

        this.s3Client =
                configService
                        .getLocalstackEndpointUri()
                        .map(endpoint -> new EndpointConfiguration(endpoint, awsRegion))
                        .map(standard()::withEndpointConfiguration)
                        .orElse(standard().withRegion(awsRegion))
                        .build();

        this.clock = Clock.systemUTC();
    }

    protected S3Service(AmazonS3 s3Client, String bucket, Clock clock) {
        this.s3Client = s3Client;
        this.bucket = bucket;
        this.clock = clock;
    }

    public void storeRecords(String payloads) {
        var key = FORMATTER.format(clock.instant()) + "-" + hashSha256String(payloads) + ".json";

        this.s3Client.putObject(this.bucket, key, payloads);
    }
}
