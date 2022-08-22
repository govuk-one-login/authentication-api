package uk.gov.di.authentication.shared.services;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.auth.credentials.EnvironmentVariableCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.sns.SnsClient;
import software.amazon.awssdk.services.sns.model.PublishRequest;
import uk.gov.di.authentication.shared.configuration.AuditPublisherConfiguration;

import java.net.URI;

public class SnsService {

    private final String topicArn;
    private final SnsClient snsClient;
    private static final Logger LOG = LogManager.getLogger(SnsService.class);

    public SnsService(AuditPublisherConfiguration configService) {
        this.topicArn = configService.getEventsSnsTopicArn();
        var localstackEndpointUri = configService.getLocalstackEndpointUri();
        var awsRegion = configService.getAwsRegion();
        if (localstackEndpointUri.isPresent()) {
            LOG.info("Localstack endpoint URI is present: " + localstackEndpointUri.get());
            snsClient =
                    SnsClient.builder()
                            .region(Region.of(awsRegion))
                            .credentialsProvider(EnvironmentVariableCredentialsProvider.create())
                            .endpointOverride(URI.create(localstackEndpointUri.get()))
                            .build();
        } else {
            snsClient = SnsClient.builder().region(Region.of(awsRegion)).build();
        }
    }

    public void publishAuditMessage(String message) {
        snsClient.publish(PublishRequest.builder().message(message).topicArn(topicArn).build());
    }
}
