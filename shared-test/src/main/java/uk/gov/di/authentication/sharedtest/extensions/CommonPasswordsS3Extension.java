package uk.gov.di.authentication.sharedtest.extensions;

import com.amazonaws.services.s3.model.PutObjectRequest;
import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

import java.io.File;
import java.net.URL;
import java.nio.file.Paths;

public class CommonPasswordsS3Extension extends S3Extension
        implements AfterEachCallback, BeforeEachCallback {
    public static final String COMMON_PASSWORDS_BUCKET = "local-common-passwords";
    public static final String TEST_FILE_NAME = "local-common-passwords-test-file";

    @Override
    public void beforeEach(ExtensionContext context) throws Exception {
        addTestFileToCommonPasswordsBucket();
    }

    @Override
    public void afterEach(ExtensionContext context) throws Exception {
        deleteS3Bucket(COMMON_PASSWORDS_BUCKET);
    }

    @Override
    protected void createBuckets() {
        if (!bucketExists(COMMON_PASSWORDS_BUCKET)) {
            s3Client.createBucket(COMMON_PASSWORDS_BUCKET);
        }
    }

    private void addTestFileToCommonPasswordsBucket() throws Exception {
        URL testFileUrl =
                Thread.currentThread()
                        .getContextClassLoader()
                        .getResource("common_passwords_integration_test.txt");
        try {
            File testFile = Paths.get(testFileUrl.toURI()).toFile();
            PutObjectRequest request =
                    new PutObjectRequest(COMMON_PASSWORDS_BUCKET, TEST_FILE_NAME, testFile);
            s3Client.putObject(request);
        } catch (Exception e) {
            throw e;
        }
    }
}
