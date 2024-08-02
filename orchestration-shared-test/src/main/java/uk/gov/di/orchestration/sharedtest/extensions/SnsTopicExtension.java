package uk.gov.di.orchestration.sharedtest.extensions;

import org.junit.jupiter.api.extension.AfterAllCallback;
import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.testcontainers.Testcontainers;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.sns.SnsClient;
import software.amazon.awssdk.services.sns.model.CreateTopicRequest;
import software.amazon.awssdk.services.sns.model.SubscribeRequest;
import uk.gov.di.orchestration.sharedtest.httpstub.HttpStubExtension;

import java.security.SecureRandom;

import static java.text.MessageFormat.format;
import static java.util.concurrent.TimeUnit.SECONDS;
import static org.awaitility.Awaitility.await;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.greaterThan;

public class SnsTopicExtension extends BaseAwsResourceExtension
        implements BeforeEachCallback, AfterAllCallback {

    private final String topicNameSuffix;
    private final SnsClient snsClient;
    private final SecureRandom secureRandom = new SecureRandom();
    private String topicArn;

    public SnsTopicExtension(String topicNameSuffix) {
        super();
        this.topicNameSuffix = topicNameSuffix;
        this.snsClient =
                SnsClient.builder()
                        .endpointOverride(LOCALSTACK_ENDPOINT)
                        .credentialsProvider(LOCALSTACK_CREDENTIALS_PROVIDER)
                        .region(Region.of(REGION))
                        .build();
    }

    @RegisterExtension protected static final HttpStubExtension httpStub = new HttpStubExtension();

    @Override
    @java.lang.SuppressWarnings("java:S2245")
    public void beforeEach(ExtensionContext context) {
        httpStub.startStub();
        Testcontainers.exposeHostPorts(httpStub.getHttpPort());
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
        await().atMost(1, SECONDS)
                .untilAsserted(() -> assertThat(httpStub.getCountOfRequests(), greaterThan(0)));
        httpStub.clearRequests();
    }

    private String createTopic(String topicName) {
        var result = snsClient.createTopic(CreateTopicRequest.builder().name(topicName).build());
        return result.topicArn();
    }

    private void subscribeToTopic(String topicArn) {
        String url =
                format(
                        "http://{0}:{1,number,#}/subscriber",
                        LOCALSTACK_HOST_HOSTNAME, httpStub.getHttpPort());
        var subscribeRequest =
                SubscribeRequest.builder()
                        .topicArn(topicArn)
                        .protocol("http")
                        .endpoint(url)
                        .build();
        snsClient.subscribe(subscribeRequest);
    }

    private void initSubscriber() {
        httpStub.register("/subscriber", 200);
    }

    public void afterAll(ExtensionContext context) throws Exception {
        httpStub.afterAll(context);
    }
}
