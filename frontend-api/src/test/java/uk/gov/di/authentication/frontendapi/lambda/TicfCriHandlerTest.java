package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.google.gson.JsonArray;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.ArgumentMatchers;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

import static java.lang.String.format;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.entity.TICFCRIRequest.basicTicfCriRequest;

class TicfCriHandlerTest {

    public static final boolean USER_IS_AUTHENTICATED = true;
    @Mock private Context context;
    @Mock private ConfigurationService configurationService;
    @Mock private CloudwatchMetricsService cloudwatchMetricsService;
    @Mock private HttpClient httpClient;
    @Mock private HttpResponse httpResponse;

    private TicfCriHandler handler;

    private static final String SERVICE_URI = "http://www.example.com";
    private static final String COMMON_SUBJECTID = "a-subject-id";
    private static final String JOURNEY_ID = "journey-id";
    private static final List<String> VECTORS_OF_TRUST = List.of("Cl");
    private AutoCloseable mocks;
    private static final Map<String, String> METRICS_CONTEXT =
            Map.of("Environment", "test-environment");

    @BeforeEach
    void setUp() {
        mocks = MockitoAnnotations.openMocks(this);
        when(configurationService.getTicfCriServiceURI()).thenReturn(SERVICE_URI);
        when(configurationService.getTicfCriServiceCallTimeout()).thenReturn(1000L);
        when(configurationService.getEnvironment()).thenReturn("test-environment");
        handler = new TicfCriHandler(httpClient, configurationService, cloudwatchMetricsService);
    }

    @AfterEach
    void tearDown() throws Exception {
        mocks.close();
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldMakeTheCorrectCallToTheTicfCri(boolean userIsAuthenticated)
            throws IOException, InterruptedException, ExecutionException {
        var ticfRequest =
                basicTicfCriRequest(
                        COMMON_SUBJECTID, VECTORS_OF_TRUST, JOURNEY_ID, userIsAuthenticated);
        var expectedRequestBody =
                format(
                        "{\"sub\":\"%s\",\"vtr\":%s,\"govuk_signin_journey_id\":\"%s\",\"authenticated\":\"%s\"}",
                        COMMON_SUBJECTID,
                        jsonArrayFrom(VECTORS_OF_TRUST),
                        JOURNEY_ID,
                        userIsAuthenticated ? "Y" : "N");

        when(httpResponse.statusCode()).thenReturn(200);
        when(httpClient.send(any(), any())).thenReturn(httpResponse);
        handler.handleRequest(ticfRequest, context);

        var httpRequestCaptor = ArgumentCaptor.forClass(HttpRequest.class);
        verify(httpClient).send(httpRequestCaptor.capture(), ArgumentMatchers.any());

        var actualRequestBody =
                bodyPublisherToString(httpRequestCaptor.getValue().bodyPublisher().get());

        var expectedUri = URI.create(SERVICE_URI + "/auth");
        assertEquals(expectedUri, httpRequestCaptor.getValue().uri());
        assertEquals(expectedRequestBody, actualRequestBody);
    }

    @ParameterizedTest
    @MethodSource("statusCodes")
    void sendsMetricsBasedOnTheHttpStatusCode(Integer statusCode)
            throws IOException, InterruptedException {
        var ticfRequest =
                basicTicfCriRequest(
                        COMMON_SUBJECTID, VECTORS_OF_TRUST, JOURNEY_ID, USER_IS_AUTHENTICATED);
        when(httpResponse.statusCode()).thenReturn(statusCode);
        when(httpClient.send(any(), any())).thenReturn(httpResponse);

        handler.handleRequest(ticfRequest, context);

        verify(cloudwatchMetricsService)
                .incrementCounter(
                        "TicfCriResponseReceived",
                        Map.ofEntries(
                                Map.entry("Environment", "test-environment"),
                                Map.entry("StatusCode", statusCode.toString())));
    }

    private static List<Arguments> statusCodes() {
        return List.of(Arguments.of(200), Arguments.of(404), Arguments.of(500));
    }

    @ParameterizedTest
    @MethodSource("exceptions")
    void testIncrementsMetricWhenAnExceptionOccurs(Exception e, String metricName)
            throws Exception {
        when(httpClient.send(any(), any())).thenThrow(e);

        handler.handleRequest(
                basicTicfCriRequest(
                        COMMON_SUBJECTID, VECTORS_OF_TRUST, JOURNEY_ID, USER_IS_AUTHENTICATED),
                context);

        verify(cloudwatchMetricsService).incrementCounter(metricName, METRICS_CONTEXT);
    }

    private static List<Arguments> exceptions() {
        return List.of(
                Arguments.of(new IOException("an IO Exception"), "TicfCriServiceError"),
                Arguments.of(
                        new InterruptedException("an Interrputed exception"),
                        "TicfCriServiceError"),
                Arguments.of(
                        new HttpTimeoutException("request timed out"), "TicfCriServiceTimeout"));
    }

    private JsonArray jsonArrayFrom(List<String> elements) {
        var jsonArray = new JsonArray();
        elements.forEach(jsonArray::add);
        return jsonArray;
    }

    private String bodyPublisherToString(HttpRequest.BodyPublisher bodyPublisher)
            throws ExecutionException, InterruptedException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        CompletableFuture<Void> future = new CompletableFuture<>();
        bodyPublisher.subscribe(
                new java.util.concurrent.Flow.Subscriber<java.nio.ByteBuffer>() {
                    @Override
                    public void onSubscribe(java.util.concurrent.Flow.Subscription subscription) {
                        subscription.request(Long.MAX_VALUE);
                    }

                    @Override
                    public void onNext(java.nio.ByteBuffer item) {
                        byteArrayOutputStream.write(
                                item.array(), item.arrayOffset(), item.remaining());
                    }

                    @Override
                    public void onError(Throwable throwable) {
                        future.completeExceptionally(throwable);
                    }

                    @Override
                    public void onComplete() {
                        future.complete(null);
                    }
                });
        future.get();
        return byteArrayOutputStream.toString(StandardCharsets.UTF_8);
    }
}
