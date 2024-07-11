package uk.gov.di.accountmanagement.services;

import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.sns.SnsClient;
import software.amazon.awssdk.services.sns.model.PublishRequest;

public class AwsSnsClient {
    private final SnsClient snsClient;
    private final String topicArn;

    public AwsSnsClient(String region, String topicArn) {
        this.snsClient = SnsClient.builder().region(Region.of(region)).build();
        this.topicArn = topicArn;
    }

    public void publish(String message) throws SdkClientException {
        var publishRequest = PublishRequest.builder().message(message).topicArn(topicArn).build();
        snsClient.publish(publishRequest);
    }
}
