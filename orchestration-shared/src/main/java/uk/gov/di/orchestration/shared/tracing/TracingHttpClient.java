package uk.gov.di.orchestration.shared.tracing;

import io.opentelemetry.api.GlobalOpenTelemetry;
import io.opentelemetry.instrumentation.httpclient.JavaHttpClientTelemetry;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.orchestration.shared.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.orchestration.shared.helpers.LogLineHelper;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;

import java.io.IOException;
import java.net.Authenticator;
import java.net.CookieHandler;
import java.net.ProxySelector;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;

@ExcludeFromGeneratedCoverageReport
public class TracingHttpClient extends HttpClient {
    private static final Logger LOG = LogManager.getLogger();
    private static final List<String> HTTP_ERROR_MESSAGES_TO_RETRY =
            List.of("GOAWAY received", "Connection reset");
    private static final Duration MAX_CLIENT_AGE = Duration.ofHours(1);
    private HttpClient baseClient;
    private Instant creationTime;

    private TracingHttpClient(HttpClient baseClient) {
        this.baseClient = baseClient;
        this.creationTime = Instant.now();
    }

    public static HttpClient newHttpClient() {
        return new TracingHttpClient(
                JavaHttpClientTelemetry.builder(GlobalOpenTelemetry.get())
                        .build()
                        .newHttpClient(HttpClient.newHttpClient()));
    }

    // Synchronize to prevent race conditions when multiple threads attempt to recreate client
    private synchronized void recreateBaseClientIfNecessary() {
        if (creationTime.plus(MAX_CLIENT_AGE).isBefore(Instant.now())) {
            LOG.info("Recreating base HTTP client due to age");
            this.baseClient = HttpClient.newHttpClient();
            this.creationTime = Instant.now(); // Reset creation time
        }
    }

    @Override
    public Optional<CookieHandler> cookieHandler() {
        return baseClient.cookieHandler();
    }

    @Override
    public Optional<Duration> connectTimeout() {
        return baseClient.connectTimeout();
    }

    @Override
    public Redirect followRedirects() {
        return baseClient.followRedirects();
    }

    @Override
    public Optional<ProxySelector> proxy() {
        return baseClient.proxy();
    }

    @Override
    public SSLContext sslContext() {
        return baseClient.sslContext();
    }

    @Override
    public SSLParameters sslParameters() {
        return baseClient.sslParameters();
    }

    @Override
    public Optional<Authenticator> authenticator() {
        return baseClient.authenticator();
    }

    @Override
    public Version version() {
        return baseClient.version();
    }

    @Override
    public Optional<Executor> executor() {
        return baseClient.executor();
    }

    @Override
    public <T> HttpResponse<T> send(
            HttpRequest request, HttpResponse.BodyHandler<T> responseBodyHandler)
            throws IOException, InterruptedException {
        // PYIC-7590: Recreate the HTTP client, to avoid HTTP/2 connection issues.
        // Check for client is 1hour old, and recreate if older.
        recreateBaseClientIfNecessary();
        try {
            return baseClient.send(request, responseBodyHandler);
        } catch (IOException e) {
            // We see occasional HTTP/2 GOAWAY messages from AWS when connections last
            // for a long time (>1 hour). Retry them once, to recreate the connection.
            // In the build environment we see connection resets for idle connections in
            // the pool. Retrying uses a different connection.
            if (HTTP_ERROR_MESSAGES_TO_RETRY.contains(e.getMessage())) {
                LOG.warn(
                        LogLineHelper.buildErrorMessage("Retrying after HTTP IOException", e)
                                .with("host", request.uri().getHost()));
                return baseClient.send(request, responseBodyHandler);
            }
            throw e;
        }
    }

    @Override
    public <T> CompletableFuture<HttpResponse<T>> sendAsync(
            HttpRequest request, HttpResponse.BodyHandler<T> responseBodyHandler) {
        throw new UnsupportedOperationException(
                "TracingHttpClient does not support async requests yet");
    }

    @Override
    public <T> CompletableFuture<HttpResponse<T>> sendAsync(
            HttpRequest request,
            HttpResponse.BodyHandler<T> responseBodyHandler,
            HttpResponse.PushPromiseHandler<T> pushPromiseHandler) {
        throw new UnsupportedOperationException(
                "TracingHttpClient does not support async requests yet");
    }
}
