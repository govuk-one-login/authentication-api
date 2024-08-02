package uk.gov.di.orchestration.sharedtest.extensions;

import org.testcontainers.containers.localstack.LocalStackContainer;
import org.testcontainers.containers.localstack.LocalStackContainer.Service;
import org.testcontainers.utility.DockerImageName;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;

import java.net.URI;

public abstract class BaseAwsResourceExtension {
    private static final DockerImageName LOCALSTACK_IMAGE =
            DockerImageName.parse("localstack/localstack:3.0.0");

    protected static final LocalStackContainer LOCALSTACK_CONTAINER;

    static {
        LOCALSTACK_CONTAINER =
                new LocalStackContainer(LOCALSTACK_IMAGE)
                        .withEnv("TEST_AWS_ACCOUNT_ID", "123456789012")
                        .withEnv("SQS_ENDPOINT_STRATEGY", "dynamic")
                        .withAccessToHost(true)
                        .withServices(
                                Service.IAM,
                                Service.EC2,
                                Service.SQS,
                                Service.S3,
                                Service.STS,
                                Service.KMS,
                                Service.SNS,
                                Service.SSM,
                                Service.CLOUDWATCH,
                                Service.DYNAMODB,
                                LocalStackContainer.EnabledService.named("events"));
        LOCALSTACK_CONTAINER.start();
    }

    protected static final String REGION = LOCALSTACK_CONTAINER.getRegion();
    protected static final String LOCALSTACK_HOST_HOSTNAME = "host.testcontainers.internal";
    protected static final URI LOCALSTACK_ENDPOINT = LOCALSTACK_CONTAINER.getEndpoint();
    protected static final StaticCredentialsProvider LOCALSTACK_CREDENTIALS_PROVIDER =
            StaticCredentialsProvider.create(
                    AwsBasicCredentials.create(
                            LOCALSTACK_CONTAINER.getAccessKey(),
                            LOCALSTACK_CONTAINER.getSecretKey()));

    public final String getRegion() {
        return REGION;
    }

    public final String getLocalstackEndpoint() {
        return LOCALSTACK_ENDPOINT.toString();
    }
}
