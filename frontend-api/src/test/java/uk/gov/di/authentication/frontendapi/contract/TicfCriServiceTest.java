package uk.gov.di.authentication.frontendapi.contract;

import au.com.dius.pact.consumer.MockServer;
import au.com.dius.pact.consumer.dsl.DslPart;
import au.com.dius.pact.consumer.dsl.PactDslWithProvider;
import au.com.dius.pact.consumer.junit.MockServerConfig;
import au.com.dius.pact.consumer.junit5.PactConsumerTest;
import au.com.dius.pact.consumer.junit5.PactTestFor;
import au.com.dius.pact.core.model.PactSpecVersion;
import au.com.dius.pact.core.model.RequestResponsePact;
import au.com.dius.pact.core.model.annotations.Pact;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.entity.InternalTICFCRIRequest;
import uk.gov.di.authentication.frontendapi.lambda.TicfCriHandler;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.sharedtest.logging.CaptureLoggingExtension;

import java.net.http.HttpClient;
import java.util.List;

import static au.com.dius.pact.consumer.dsl.LambdaDsl.newJsonBody;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasItem;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.sharedtest.logging.LogEventMatcher.withMessageContaining;

@PactConsumerTest
@MockServerConfig(hostInterface = "localhost", port = "1234")
class TicfCriServiceTest {
    private final ConfigurationService configService = mock(ConfigurationService.class);
    private final CloudwatchMetricsService cloudwatchMetricsService =
            mock(CloudwatchMetricsService.class);
    private final HttpClient httpClient = HttpClient.newHttpClient();
    private TicfCriHandler ticfCriHandler;

    private static final String PROVIDER_NAME = "TicfCriProvider";
    private static final String CONSUMER_NAME = "AuthTicfCriServiceConsumer";
    private static final String INTERNAL_PAIRWISE_ID = "urn:fdc:gov.uk:2022:test-subject-id";
    private static final String JOURNEY_ID = "test-journey-id";
    private static final Long TICF_CALL_TIMEOUT = 2000L;

    @RegisterExtension
    public final CaptureLoggingExtension logging =
            new CaptureLoggingExtension(TicfCriHandler.class);

    @BeforeEach
    void setup() {
        when(configService.getTicfCriServiceCallTimeout()).thenReturn(TICF_CALL_TIMEOUT);
        when(configService.getEnvironment()).thenReturn("test");
    }

    @Pact(provider = PROVIDER_NAME, consumer = CONSUMER_NAME)
    RequestResponsePact createSuccessfulAuthenticationPact(PactDslWithProvider builder) {
        return builder.given("TICF CRI service is available")
                .uponReceiving("a request for successful authentication")
                .path("/auth")
                .method("POST")
                .willRespondWith()
                .status(202)
                .body(createTicfResponseBody())
                .toPact();
    }

    @Test
    @PactTestFor(
            providerName = PROVIDER_NAME,
            pactMethod = "createSuccessfulAuthenticationPact",
            pactVersion = PactSpecVersion.V3)
    void sendsRequestForSuccessfulAuthentication(MockServer mockServer) {
        when(configService.getTicfCriServiceURI()).thenReturn(mockServer.getUrl());
        ticfCriHandler = new TicfCriHandler(httpClient, configService, cloudwatchMetricsService);

        var request =
                new InternalTICFCRIRequest(
                        INTERNAL_PAIRWISE_ID,
                        List.of("Cl.Cm"),
                        JOURNEY_ID,
                        true,
                        AuthSessionItem.AccountState.EXISTING,
                        AuthSessionItem.ResetPasswordState.NONE,
                        AuthSessionItem.ResetMfaState.NONE,
                        MFAMethodType.SMS);

        assertDoesNotThrow(() -> ticfCriHandler.handleRequest(request, null));
        verify(configService).getTicfCriServiceURI();
    }

    @Pact(provider = PROVIDER_NAME, consumer = CONSUMER_NAME)
    RequestResponsePact createFailedAuthenticationPact(PactDslWithProvider builder) {
        return builder.given("TICF CRI service is available")
                .uponReceiving("a request for failed authentication")
                .path("/auth")
                .method("POST")
                .willRespondWith()
                .status(202)
                .body(createTicfResponseBody())
                .toPact();
    }

    @Test
    @PactTestFor(
            providerName = PROVIDER_NAME,
            pactMethod = "createFailedAuthenticationPact",
            pactVersion = PactSpecVersion.V3)
    void sendsRequestForFailedAuthentication(MockServer mockServer) {
        when(configService.getTicfCriServiceURI()).thenReturn(mockServer.getUrl());
        ticfCriHandler = new TicfCriHandler(httpClient, configService, cloudwatchMetricsService);

        var request =
                new InternalTICFCRIRequest(
                        INTERNAL_PAIRWISE_ID,
                        List.of("Cl.Cm"),
                        JOURNEY_ID,
                        false,
                        AuthSessionItem.AccountState.EXISTING,
                        AuthSessionItem.ResetPasswordState.ATTEMPTED,
                        AuthSessionItem.ResetMfaState.NONE,
                        MFAMethodType.SMS);

        assertDoesNotThrow(() -> ticfCriHandler.handleRequest(request, null));
        verify(configService).getTicfCriServiceURI();
    }

    @Pact(provider = PROVIDER_NAME, consumer = CONSUMER_NAME)
    RequestResponsePact createIncompleteRequestPact(PactDslWithProvider builder) {
        return builder.given("TICF CRI service is available")
                .uponReceiving("a request with missing required fields")
                .path("/auth")
                .method("POST")
                .willRespondWith()
                .status(400)
                .toPact();
    }

    @Pact(provider = PROVIDER_NAME, consumer = CONSUMER_NAME)
    RequestResponsePact createServerErrorPact(PactDslWithProvider builder) {
        return builder.given("TICF CRI service has internal error")
                .uponReceiving("a request when service is experiencing issues")
                .path("/auth")
                .method("POST")
                .willRespondWith()
                .status(500)
                .toPact();
    }

    @Test
    @PactTestFor(
            providerName = PROVIDER_NAME,
            pactMethod = "createIncompleteRequestPact",
            pactVersion = PactSpecVersion.V3)
    void sendsIncompleteRequest(MockServer mockServer) {
        when(configService.getTicfCriServiceURI()).thenReturn(mockServer.getUrl());
        ticfCriHandler = new TicfCriHandler(httpClient, configService, cloudwatchMetricsService);

        var request =
                new InternalTICFCRIRequest(
                        null, // Missing required sub
                        null, // Missing required vtr
                        null, // Missing required govukSigninJourneyId
                        true,
                        AuthSessionItem.AccountState.EXISTING,
                        AuthSessionItem.ResetPasswordState.NONE,
                        AuthSessionItem.ResetMfaState.NONE,
                        MFAMethodType.SMS);

        assertDoesNotThrow(() -> ticfCriHandler.handleRequest(request, null));
        verify(configService).getTicfCriServiceURI();
        assertThat(
                logging.events(),
                hasItem(
                        withMessageContaining(
                                "Response received from TICF CRI Service with status 400")));
    }

    @Test
    @PactTestFor(
            providerName = PROVIDER_NAME,
            pactMethod = "createServerErrorPact",
            pactVersion = PactSpecVersion.V3)
    void handlesServerError(MockServer mockServer) {
        when(configService.getTicfCriServiceURI()).thenReturn(mockServer.getUrl());
        ticfCriHandler = new TicfCriHandler(httpClient, configService, cloudwatchMetricsService);

        var request =
                new InternalTICFCRIRequest(
                        INTERNAL_PAIRWISE_ID,
                        List.of("Cl.Cm"),
                        JOURNEY_ID,
                        true,
                        AuthSessionItem.AccountState.EXISTING,
                        AuthSessionItem.ResetPasswordState.NONE,
                        AuthSessionItem.ResetMfaState.NONE,
                        MFAMethodType.SMS);

        assertDoesNotThrow(() -> ticfCriHandler.handleRequest(request, null));
        verify(configService).getTicfCriServiceURI();
        assertThat(
                logging.events(),
                hasItem(
                        withMessageContaining(
                                "Response received from TICF CRI Service with status 500")));
    }

    private static DslPart createTicfResponseBody() {
        return newJsonBody(
                        body -> {
                            body.object(
                                    "intervention",
                                    obj -> {
                                        obj.stringType("interventionCode", "01");
                                        obj.stringType("interventionReason", "01");
                                    });
                            body.stringType("sub", INTERNAL_PAIRWISE_ID);
                            body.stringType("govuk_signin_journey_id", JOURNEY_ID);
                            body.array(
                                    "ci",
                                    arr -> {
                                        arr.stringValue("D03");
                                        arr.stringValue("F01");
                                    });
                        })
                .build();
    }
}
