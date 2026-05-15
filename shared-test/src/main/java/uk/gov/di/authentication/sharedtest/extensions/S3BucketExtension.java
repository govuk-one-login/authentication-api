package uk.gov.di.authentication.sharedtest.extensions;

import org.junit.jupiter.api.extension.AfterAllCallback;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.S3Configuration;
import software.amazon.awssdk.services.s3.model.CreateBucketRequest;
import software.amazon.awssdk.services.s3.model.DeleteBucketRequest;
import software.amazon.awssdk.services.s3.model.DeleteObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.HeadBucketRequest;
import software.amazon.awssdk.services.s3.model.ListObjectsRequest;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.S3Exception;

import java.io.IOException;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;

public class S3BucketExtension extends BaseAwsResourceExtension
        implements BeforeAllCallback, AfterAllCallback {

    private static final S3Client s3Client =
            S3Client.builder()
                    .endpointOverride(URI.create(LOCALSTACK_ENDPOINT))
                    .region(Region.of(REGION))
                    .credentialsProvider(
                            StaticCredentialsProvider.create(
                                    AwsBasicCredentials.create("access", "secret")))
                    .serviceConfiguration(
                            S3Configuration.builder().pathStyleAccessEnabled(true).build())
                    .build();

    private final String bucketName;
    private final String fileKey;
    private final String classpathResource;

    public S3BucketExtension(String bucketName, String fileKey, String classpathResource) {
        this.bucketName = bucketName;
        this.fileKey = fileKey;
        this.classpathResource = classpathResource;
    }

    public S3BucketExtension(String bucketName) {
        this(bucketName, null, null);
    }

    @Override
    public void beforeAll(ExtensionContext context) throws Exception {
        if (!bucketExists(bucketName)) {
            s3Client.createBucket(CreateBucketRequest.builder().bucket(bucketName).build());
        }
        if (classpathResource != null) {
            URL testFileUrl =
                    Thread.currentThread().getContextClassLoader().getResource(classpathResource);
            s3Client.putObject(
                    PutObjectRequest.builder().bucket(bucketName).key(fileKey).build(),
                    Paths.get(testFileUrl.toURI()));
        }
    }

    @Override
    public void afterAll(ExtensionContext context) {
        if (bucketExists(bucketName)) {
            s3Client.listObjects(ListObjectsRequest.builder().bucket(bucketName).build())
                    .contents()
                    .forEach(
                            t ->
                                    s3Client.deleteObject(
                                            DeleteObjectRequest.builder()
                                                    .bucket(bucketName)
                                                    .key(t.key())
                                                    .build()));
            s3Client.deleteBucket(DeleteBucketRequest.builder().bucket(bucketName).build());
        }
    }

    public String getObject(String key) throws IOException {
        return new String(
                s3Client.getObject(GetObjectRequest.builder().bucket(bucketName).key(key).build())
                        .readAllBytes(),
                StandardCharsets.UTF_8);
    }

    private boolean bucketExists(String bucketName) {
        try {
            s3Client.headBucket(HeadBucketRequest.builder().bucket(bucketName).build());
            return true;
        } catch (S3Exception _) {
            return false;
        }
    }
}
