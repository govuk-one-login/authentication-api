package uk.gov.di.authentication.shared.services;

import com.amazonaws.client.builder.AwsClientBuilder;
import com.amazonaws.services.sns.AmazonSNS;
import com.amazonaws.services.sns.AmazonSNSClientBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SnsService {

    private final String topicArn;
    private final AmazonSNS snsClient;
    private static final Logger LOGGER = LoggerFactory.getLogger(SnsService.class);

    public SnsService(ConfigurationService configService) {
        this.topicArn = configService.getEventsSnsTopicArn();
        var localstackEndpointUri = configService.getLocalstackEndpointUri();
        var awsRegion = configService.getAwsRegion();
        if (localstackEndpointUri.isPresent()) {
            LOGGER.info("Localstack endpoint URI is present: " + localstackEndpointUri.get());
            this.snsClient =
                    AmazonSNSClientBuilder.standard()
                            .withEndpointConfiguration(
                                    new AwsClientBuilder.EndpointConfiguration(
                                            localstackEndpointUri.get(), awsRegion))
                            .build();
        } else {
            this.snsClient = AmazonSNSClientBuilder.standard().withRegion(awsRegion).build();
        }
    }

    public void publishAuditMessage(String message) {
        snsClient.publish(topicArn, message);
    }
}
