package uk.gov.di.orchestration.sharedtest.basetest;

import au.com.dius.pact.provider.junit5.HttpTestTarget;
import au.com.dius.pact.provider.junit5.PactVerificationContext;
import au.com.dius.pact.provider.junit5.PactVerificationInvocationContextProvider;
import au.com.dius.pact.provider.junitsupport.IgnoreNoPactsToVerify;
import au.com.dius.pact.provider.junitsupport.Provider;
import au.com.dius.pact.provider.junitsupport.loader.PactBroker;
import au.com.dius.pact.provider.junitsupport.loader.PactBrokerAuth;
import au.com.dius.pact.provider.junitsupport.loader.PactBrokerConsumerVersionSelectors;
import au.com.dius.pact.provider.junitsupport.loader.SelectorBuilder;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestTemplate;
import org.junit.jupiter.api.extension.ExtendWith;
import uk.gov.di.orchestration.sharedtest.pact.LambdaHandlerConfig;
import uk.gov.di.orchestration.sharedtest.pact.LambdaHttpServer;

import java.io.IOException;
import java.util.List;
import java.util.Objects;

import static org.junit.jupiter.api.TestInstance.Lifecycle.PER_CLASS;

@TestInstance(PER_CLASS)
@Provider("${PROVIDER_UNDER_TEST}")
@PactBroker(
        url = "${PACT_URL}?testSource=${PACT_BROKER_SOURCE_HEADER}",
        authentication = @PactBrokerAuth(username = "${PACT_USER}", password = "${PACT_PASSWORD}"))
@ExtendWith(PactVerificationInvocationContextProvider.class)
public abstract class PactProviderTest extends IntegrationTest {
    private static final String HOST = "localhost";
    private static final int PORT = 5050;
    private LambdaHttpServer httpServer;

    protected abstract List<LambdaHandlerConfig> getHandlerConfig();

    @BeforeAll
    void setUpHttpServer() throws IOException {
        httpServer = new LambdaHttpServer(HOST, PORT, getHandlerConfig());
        httpServer.start();
    }

    // Ignore IntelliJ "should not declare parameter" warning. This is a false positive and should
    // be fixed in future IntelliJ release: https://youtrack.jetbrains.com/issue/IDEA-312816
    @BeforeEach
    void setUpTarget(PactVerificationContext context) {
        if (Objects.nonNull(context)) {
            context.setTarget(new HttpTestTarget(HOST, PORT));
        }
    }

    @AfterAll
    void tearDownHttpServer() {
        httpServer.stop();
    }

    @TestTemplate
    void verifyInteraction(PactVerificationContext context) {
        if (Objects.nonNull(context)) {
            context.verifyInteraction();
        }
    }

    @PactBrokerConsumerVersionSelectors
    public static SelectorBuilder consumerVersionSelectors() {
        return new SelectorBuilder().mainBranch();
    }
}
