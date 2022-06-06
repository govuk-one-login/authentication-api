package uk.gov.di.authentication.shared.services;

import com.amazonaws.client.builder.AwsClientBuilder;
import com.amazonaws.services.sns.AmazonSNSAsync;
import com.amazonaws.services.sns.AmazonSNSAsyncClientBuilder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.shared.configuration.AuditPublisherConfiguration;

public class SnsService {

    private final String topicArn;
    private final AmazonSNSAsync snsClient;
    private static final Logger LOG = LogManager.getLogger(SnsService.class);

    public SnsService(AuditPublisherConfiguration configService) {
        this.topicArn = configService.getEventsSnsTopicArn();
        var localstackEndpointUri = configService.getLocalstackEndpointUri();
        var awsRegion = configService.getAwsRegion();
        if (localstackEndpointUri.isPresent()) {
            LOG.info("Localstack endpoint URI is present: " + localstackEndpointUri.get());
            this.snsClient =
                    AmazonSNSAsyncClientBuilder.standard()
                            .withEndpointConfiguration(
                                    new AwsClientBuilder.EndpointConfiguration(
                                            localstackEndpointUri.get(), awsRegion))
                            .build();
        } else {
            this.snsClient = AmazonSNSAsyncClientBuilder.standard().withRegion(awsRegion).build();
        }
    }

    public void publishAuditMessage(String message) {
        snsClient.publishAsync(topicArn, message);
    }
}
