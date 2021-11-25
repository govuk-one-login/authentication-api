package uk.gov.di.authentication.sharedtest.extensions;

import com.amazonaws.client.builder.AwsClientBuilder;
import com.amazonaws.services.sns.AmazonSNS;
import com.amazonaws.services.sns.AmazonSNSClientBuilder;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

import static java.text.MessageFormat.format;

public class SnsTopicExtension implements BeforeAllCallback {

    protected static final String REGION = System.getenv().getOrDefault("AWS_REGION", "eu-west-2");
    protected static final String LOCALSTACK_ENDPOINT =
            System.getenv().getOrDefault("LOCALSTACK_ENDPOINT", "http://localhost:45678");

    private final String topicNameSuffix;
    private final AmazonSNS snsClient;

    private String topicArn;

    public SnsTopicExtension(String topicNameSuffix) {
        this.topicNameSuffix = topicNameSuffix;
        this.snsClient =
                AmazonSNSClientBuilder.standard()
                        .withEndpointConfiguration(
                                new AwsClientBuilder.EndpointConfiguration(
                                        LOCALSTACK_ENDPOINT, REGION))
                        .build();
    }

    @Override
    public void beforeAll(ExtensionContext context) {
        var topicName =
                format(
                        "{0}-{1}",
                        context.getTestClass().map(Class::getSimpleName).orElse("unknown"),
                        topicNameSuffix);

        topicArn = createTopic(topicName);
    }

    public String getTopicArn() {
        return topicArn;
    }

    private String createTopic(String topicName) {
        var result = snsClient.createTopic(topicName);
        return result.getTopicArn();
    }
}
