package uk.gov.di.authentication.sharedtest.extensions;

import software.amazon.awssdk.services.s3.model.CreateBucketRequest;
import software.amazon.awssdk.services.s3.model.DeleteBucketRequest;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;

import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Paths;

public class BulkTestUserS3Extension extends S3Extension {
    public static final String BULK_TEST_USER_BUCKET = "local-bulk-test-user";
    public static final String TEST_FILE_NAME = "local-bulk-test-user-test-file";

    @Override
    protected void createBuckets() throws URISyntaxException {
        if (!bucketExists(BULK_TEST_USER_BUCKET)) {
            s3Client.createBucket(
                    CreateBucketRequest.builder().bucket(BULK_TEST_USER_BUCKET).build());
        }

        addTestFileToBulkTestUsersBucket();
    }

    @Override
    protected void deleteBuckets() {
        if (bucketExists(BULK_TEST_USER_BUCKET)) {
            deleteS3BucketContents(BULK_TEST_USER_BUCKET);
            s3Client.deleteBucket(
                    DeleteBucketRequest.builder().bucket(BULK_TEST_USER_BUCKET).build());
        }
    }

    private void addTestFileToBulkTestUsersBucket() throws URISyntaxException {
        URL testFileUrl =
                Thread.currentThread()
                        .getContextClassLoader()
                        .getResource("test_users_integration_test.txt");

        var putObjectRequest =
                PutObjectRequest.builder()
                        .bucket(BULK_TEST_USER_BUCKET)
                        .key(TEST_FILE_NAME)
                        .build();
        s3Client.putObject(putObjectRequest, Paths.get(testFileUrl.toURI()));
    }
}
