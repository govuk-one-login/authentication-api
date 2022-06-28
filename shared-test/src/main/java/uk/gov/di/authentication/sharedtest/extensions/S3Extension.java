package uk.gov.di.authentication.sharedtest.extensions;

import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.client.builder.AwsClientBuilder;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3Client;
import com.amazonaws.services.s3.iterable.S3Objects;
import com.amazonaws.services.s3.model.AmazonS3Exception;
import com.amazonaws.services.s3.model.HeadBucketRequest;
import com.amazonaws.services.s3.model.S3ObjectSummary;
import org.junit.jupiter.api.extension.AfterAllCallback;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

import java.net.URISyntaxException;

public abstract class S3Extension extends BaseAwsResourceExtension
        implements BeforeAllCallback, AfterAllCallback {

    protected static final AmazonS3 s3Client =
            AmazonS3Client.builder()
                    .withEndpointConfiguration(
                            new AwsClientBuilder.EndpointConfiguration(LOCALSTACK_ENDPOINT, REGION))
                    .withCredentials(
                            new AWSStaticCredentialsProvider(
                                    new BasicAWSCredentials("access", "secret")))
                    .withPathStyleAccessEnabled(true)
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
            final HeadBucketRequest request = new HeadBucketRequest(bucketName);
            s3Client.headBucket(request);
            return true;
        } catch (AmazonS3Exception ignored) {
            return false;
        }
    }

    protected void deleteS3BucketContents(String bucketName) {
        S3Objects.inBucket(s3Client, bucketName)
                .forEach(
                        (S3ObjectSummary objectSummary) ->
                                s3Client.deleteObject(bucketName, objectSummary.getKey()));
    }

    abstract void deleteBuckets();
}
