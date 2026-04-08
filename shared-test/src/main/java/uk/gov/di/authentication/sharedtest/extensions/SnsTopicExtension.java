package uk.gov.di.authentication.sharedtest.extensions;

import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.sns.SnsClient;
import software.amazon.awssdk.services.sns.model.CreateTopicRequest;
import software.amazon.awssdk.services.sns.model.SubscribeRequest;
import uk.gov.di.authentication.sharedtest.httpstub.HttpStubExtension;

import java.net.URI;
import java.security.SecureRandom;

import static java.text.MessageFormat.format;
import static java.util.concurrent.TimeUnit.SECONDS;
import static org.awaitility.Awaitility.await;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.greaterThan;

public class SnsTopicExtension extends HttpStubExtension implements BeforeEachCallback {

    protected static final String REGION = System.getenv().getOrDefault("AWS_REGION", "eu-west-2");
    protected static final String LOCALSTACK_ENDPOINT =
            System.getenv().getOrDefault("LOCALSTACK_ENDPOINT", "http://localhost:45678");

    private final String topicNameSuffix;
    private final SnsClient snsClient;
    private final SecureRandom secureRandom = new SecureRandom();
    private String topicArn;

    public SnsTopicExtension(String topicNameSuffix) {
        super();
        this.topicNameSuffix = topicNameSuffix;
        this.snsClient =
                SnsClient.builder()
                        .endpointOverride(URI.create(LOCALSTACK_ENDPOINT))
                        .credentialsProvider(DefaultCredentialsProvider.builder().build())
                        .region(Region.of(REGION))
                        .build();
    }

    @Override
    @java.lang.SuppressWarnings("java:S2245")
    public void beforeEach(ExtensionContext context) {
        startStub();
        var topicName =
                format(
                        "{0}-{1}-{2}",
                        context.getTestClass().map(Class::getSimpleName).orElse("unknown"),
                        topicNameSuffix,
                        Integer.toString(secureRandom.nextInt(99999)));

        topicArn = createTopic(topicName);
        initSubscriber();
        subscribeToTopic(topicArn);

        // Wait for topic subscription message to be received, so that it doesn't pollute the tests.
        await().atMost(2, SECONDS)
                .untilAsserted(() -> assertThat(getCountOfRequests(), greaterThan(0)));
        clearRequests();
    }

    public String getTopicArn() {
        return topicArn;
    }

    private String createTopic(String topicName) {
        var result = snsClient.createTopic(CreateTopicRequest.builder().name(topicName).build());
        return result.topicArn();
    }

    private void subscribeToTopic(String topicArn) {
        String url = format("http://subscriber.internal:{0,number,#}/subscriber", getHttpPort());
        var subscribeRequest =
                SubscribeRequest.builder()
                        .topicArn(topicArn)
                        .protocol("http")
                        .endpoint(url)
                        .build();
        snsClient.subscribe(subscribeRequest);
    }

    private void initSubscriber() {
        register("/subscriber", 200);
    }
}
