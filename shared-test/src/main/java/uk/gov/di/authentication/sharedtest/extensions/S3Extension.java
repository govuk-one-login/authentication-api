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
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

public abstract class S3Extension extends BaseAwsResourceExtension implements BeforeAllCallback {

    protected AmazonS3 s3Client;
    protected static final String S3_ENDPOINT =
            System.getenv().getOrDefault("S3_ENDPOINT", "http://localhost:45678");

    @Override
    public void beforeAll(ExtensionContext context) throws Exception {
        var mockS3Credentials = new BasicAWSCredentials("access", "secret");

        s3Client =
                AmazonS3Client.builder()
                        .withEndpointConfiguration(
                                new AwsClientBuilder.EndpointConfiguration(S3_ENDPOINT, REGION))
                        .withCredentials(new AWSStaticCredentialsProvider(mockS3Credentials))
                        .withPathStyleAccessEnabled(true)
                        .build();

        createBuckets();
    }

    protected abstract void createBuckets();

    protected boolean bucketExists(String bucketName) {
        try {
            final HeadBucketRequest request = new HeadBucketRequest(bucketName);
            s3Client.headBucket(request);
            return true;
        } catch (AmazonS3Exception ignored) {
            return false;
        }
    }

    protected void deleteS3Bucket(String bucketName) {
        S3Objects.inBucket(s3Client, bucketName)
                .forEach(
                        (S3ObjectSummary objectSummary) ->
                                s3Client.deleteObject(bucketName, objectSummary.getKey()));

        s3Client.deleteBucket(bucketName);
    }
}
