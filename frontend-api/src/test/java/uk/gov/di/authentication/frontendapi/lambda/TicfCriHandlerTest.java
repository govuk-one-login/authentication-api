package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.google.gson.JsonArray;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.ArgumentMatchers;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

import static java.lang.String.format;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.entity.TICFCRIRequest.basicTicfCriRequest;

class TicfCriHandlerTest {

    @Mock private Context context;
    @Mock private ConfigurationService configurationService;
    @Mock private HttpClient httpClient;

    private TicfCriHandler handler;

    private static final URI SERVICE_URI = URI.create("http://www.example.com");
    private static final String COMMON_SUBJECTID = "a-subject-id";
    private static final String JOURNEY_ID = "journey-id";
    private static final List<String> VECTORS_OF_TRUST = List.of("Cl");
    private AutoCloseable mocks;

    @BeforeEach
    void setUp() {
        mocks = MockitoAnnotations.openMocks(this);
        when(configurationService.getTicfCriServiceURI()).thenReturn(SERVICE_URI);
        handler = new TicfCriHandler(httpClient, configurationService);
    }

    @AfterEach
    void tearDown() throws Exception {
        mocks.close();
    }

    @Test
    void shouldMakeTheCorrectCallToTheTicfCri()
            throws IOException, InterruptedException, ExecutionException {

        var ticfRequest = basicTicfCriRequest(COMMON_SUBJECTID, VECTORS_OF_TRUST, JOURNEY_ID);
        var expectedRequestBody =
                format(
                        "{\"sub\":\"%s\",\"vtr\":%s,\"govuk_signin_journey_id\":\"%s\",\"authenticated\":\"Y\",\"initial_registration\":null,\"password_reset\":null}",
                        COMMON_SUBJECTID, jsonArrayFrom(VECTORS_OF_TRUST), JOURNEY_ID);

        handler.handleRequest(ticfRequest, context);

        var httpRequestCaptor = ArgumentCaptor.forClass(HttpRequest.class);
        verify(httpClient).send(httpRequestCaptor.capture(), ArgumentMatchers.any());

        var actualRequestBody =
                bodyPublisherToString(httpRequestCaptor.getValue().bodyPublisher().get());

        assertEquals(SERVICE_URI, httpRequestCaptor.getValue().uri());
        assertEquals(expectedRequestBody, actualRequestBody);
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
