package uk.gov.di.orchestration.sharedtest.extensions;

import org.junit.jupiter.api.extension.AfterAllCallback;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.S3Configuration;
import software.amazon.awssdk.services.s3.model.DeleteObjectRequest;
import software.amazon.awssdk.services.s3.model.HeadBucketRequest;
import software.amazon.awssdk.services.s3.model.ListObjectsRequest;
import software.amazon.awssdk.services.s3.model.S3Exception;

import java.net.URI;
import java.net.URISyntaxException;

public abstract class S3Extension extends BaseAwsResourceExtension
        implements BeforeAllCallback, AfterAllCallback {

    protected static final S3Client s3Client =
            S3Client.builder()
                    .endpointOverride(URI.create(LOCALSTACK_ENDPOINT))
                    .region(Region.of(REGION))
                    .credentialsProvider(
                            StaticCredentialsProvider.create(
                                    AwsBasicCredentials.create("access", "secret")))
                    .serviceConfiguration(
                            S3Configuration.builder().pathStyleAccessEnabled(true).build())
                    .build();

    @Override
    public void beforeAll(ExtensionContext context) throws Exception {
        createBuckets();
    }

    @Override
    public void afterAll(ExtensionContext context) throws Exception {
        deleteBuckets();
    }

    protected abstract void createBuckets() throws URISyntaxException;

    protected boolean bucketExists(String bucketName) {
        try {
            final HeadBucketRequest request =
                    HeadBucketRequest.builder().bucket(bucketName).build();
            s3Client.headBucket(request);
            return true;
        } catch (S3Exception ignored) {
            return false;
        }
    }

    protected void deleteS3BucketContents(String bucketName) {
        var listObjectsResponse =
                s3Client.listObjects(ListObjectsRequest.builder().bucket(bucketName).build());
        listObjectsResponse
                .contents()
                .forEach(
                        t ->
                                s3Client.deleteObject(
                                        DeleteObjectRequest.builder()
                                                .bucket(bucketName)
                                                .key(t.key())
                                                .build()));
    }

    abstract void deleteBuckets();
}
