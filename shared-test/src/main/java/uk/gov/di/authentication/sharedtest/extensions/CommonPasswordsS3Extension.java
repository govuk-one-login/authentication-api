package uk.gov.di.authentication.sharedtest.extensions;

import com.amazonaws.services.s3.model.PutObjectRequest;

import java.io.File;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Paths;

public class CommonPasswordsS3Extension extends S3Extension {
    public static final String COMMON_PASSWORDS_BUCKET = "local-common-passwords";
    public static final String TEST_FILE_NAME = "local-common-passwords-test-file";

    @Override
    protected void createBuckets() throws URISyntaxException {
        if (!bucketExists(COMMON_PASSWORDS_BUCKET)) {
            s3Client.createBucket(COMMON_PASSWORDS_BUCKET);
        }

        addTestFileToCommonPasswordsBucket();
    }

    @Override
    void deleteBuckets() {
        if (bucketExists(COMMON_PASSWORDS_BUCKET)) {
            deleteS3BucketContents(COMMON_PASSWORDS_BUCKET);
            s3Client.deleteBucket(COMMON_PASSWORDS_BUCKET);
        }
    }

    private void addTestFileToCommonPasswordsBucket() throws URISyntaxException {
        URL testFileUrl =
                Thread.currentThread()
                        .getContextClassLoader()
                        .getResource("common_passwords_integration_test.txt");

        File testFile = Paths.get(testFileUrl.toURI()).toFile();
        PutObjectRequest request =
                new PutObjectRequest(COMMON_PASSWORDS_BUCKET, TEST_FILE_NAME, testFile);
        s3Client.putObject(request);
    }
}
