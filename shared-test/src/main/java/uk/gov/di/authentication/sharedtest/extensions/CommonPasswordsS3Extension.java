package uk.gov.di.authentication.sharedtest.extensions;

import software.amazon.awssdk.services.s3.model.CreateBucketRequest;
import software.amazon.awssdk.services.s3.model.DeleteBucketRequest;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;

import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Paths;

public class CommonPasswordsS3Extension extends S3Extension {
    public static final String COMMON_PASSWORDS_BUCKET =
            "local-common-passwords"; // pragma: allowlist secret
    public static final String TEST_FILE_NAME = "local-common-passwords-test-file";

    @Override
    protected void createBuckets() throws URISyntaxException {
        if (!bucketExists(COMMON_PASSWORDS_BUCKET)) {
            s3Client.createBucket(
                    CreateBucketRequest.builder().bucket(COMMON_PASSWORDS_BUCKET).build());
        }

        addTestFileToCommonPasswordsBucket();
    }

    @Override
    void deleteBuckets() {
        if (bucketExists(COMMON_PASSWORDS_BUCKET)) {
            deleteS3BucketContents(COMMON_PASSWORDS_BUCKET);
            s3Client.deleteBucket(
                    DeleteBucketRequest.builder().bucket(COMMON_PASSWORDS_BUCKET).build());
        }
    }

    private void addTestFileToCommonPasswordsBucket() throws URISyntaxException {
        URL testFileUrl =
                Thread.currentThread()
                        .getContextClassLoader()
                        .getResource("common_passwords_integration_test.txt");

        var putObjectRequest =
                PutObjectRequest.builder()
                        .bucket(COMMON_PASSWORDS_BUCKET)
                        .key(TEST_FILE_NAME)
                        .build();
        s3Client.putObject(putObjectRequest, Paths.get(testFileUrl.toURI()));
    }
}
