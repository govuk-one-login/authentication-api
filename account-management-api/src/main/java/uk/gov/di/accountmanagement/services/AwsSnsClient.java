package uk.gov.di.accountmanagement.services;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.auth.credentials.EnvironmentVariableCredentialsProvider;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.sns.SnsClient;
import software.amazon.awssdk.services.sns.model.PublishRequest;

import java.net.URI;

public class AwsSnsClient {
    private static final Logger LOG = LogManager.getLogger(AwsSnsClient.class);
    private final SnsClient snsClient;
    private final String topicArn;

    public AwsSnsClient(String region, String topicArn) {
        this.snsClient = SnsClient.builder().region(Region.of(region)).build();
        this.topicArn = topicArn;
    }

    public AwsSnsClient(String region, String topicArn, String endpointUri) {
        var builder =
                SnsClient.builder()
                        .region(Region.of(region))
                        .credentialsProvider(EnvironmentVariableCredentialsProvider.create());
        if (endpointUri != null && !endpointUri.isEmpty()) {
            builder.endpointOverride(URI.create(endpointUri));
        }
        this.snsClient = builder.build();
        this.topicArn = topicArn;
    }

    AwsSnsClient(SnsClient snsClient, String topicArn) {
        this.snsClient = snsClient;
        this.topicArn = topicArn;
    }

    public void publish(String message) throws SdkClientException {
        var publishRequest = PublishRequest.builder().message(message).topicArn(topicArn).build();
        var response = snsClient.publish(publishRequest);
        LOG.info("Message published to SNS with messageId: {}", response.messageId());
    }
}
