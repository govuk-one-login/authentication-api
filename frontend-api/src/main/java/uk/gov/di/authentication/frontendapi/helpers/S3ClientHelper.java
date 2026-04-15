package uk.gov.di.authentication.frontendapi.helpers;

import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.S3Configuration;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.net.URI;

public class S3ClientHelper {
    private S3ClientHelper() {
        /* This utility class should not be instantiated */
    }

    public static S3Client createLocalstackS3Client(
            ConfigurationService configurationService, String endpointOverride) {
        var fakeCredentials = AwsBasicCredentials.create("FAKEACCESSKEY", "FAKESECRETKEY");
        var s3Configuration = S3Configuration.builder().pathStyleAccessEnabled(true).build();
        return S3Client.builder()
                .endpointOverride(URI.create(endpointOverride))
                .region(Region.of(configurationService.getAwsRegion()))
                .credentialsProvider(StaticCredentialsProvider.create(fakeCredentials))
                .serviceConfiguration(s3Configuration)
                .build();
    }
}
