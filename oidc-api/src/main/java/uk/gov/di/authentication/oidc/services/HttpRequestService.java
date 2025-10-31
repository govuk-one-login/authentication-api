package uk.gov.di.authentication.oidc.services;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.ObjectMessage;
import uk.gov.di.authentication.oidc.exceptions.HttpRequestTimeoutException;
import uk.gov.di.authentication.oidc.exceptions.PostRequestFailureException;
import uk.gov.di.orchestration.shared.helpers.HttpClientHelper;
import uk.gov.di.orchestration.shared.services.CloudwatchMetricsService;
import uk.gov.di.orchestration.shared.services.ConfigurationService;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse.BodyHandlers;
import java.net.http.HttpTimeoutException;
import java.time.Duration;
import java.util.Map;

import static java.lang.String.format;
import static java.net.http.HttpRequest.BodyPublishers.ofString;

public class HttpRequestService {

    private static final Logger LOG = LogManager.getLogger(HttpRequestService.class);
    private static final CloudwatchMetricsService METRICS = new CloudwatchMetricsService();
    private final ConfigurationService configurationService;
    private final HttpClient httpClient;

    public HttpRequestService() {
        configurationService = new ConfigurationService();
        httpClient = HttpClientHelper.newInstrumentedHttpClient();
    }

    public HttpRequestService(ConfigurationService configService) {
        configurationService = configService;
        httpClient = HttpClientHelper.newInstrumentedHttpClient();
    }

    public void post(URI uri, String body) throws IOException {

        var request =
                HttpRequest.newBuilder()
                        .uri(uri)
                        .POST(ofString(body))
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .timeout(
                                Duration.ofMillis(
                                        configurationService.getBackChannelLogoutCallTimeout()))
                        .build();

        try {
            var response = httpClient.send(request, BodyHandlers.discarding());

            var statusCode = Integer.toString(response.statusCode());

            var logMessage = Map.of("uri", uri.toString(), "response-code", statusCode);

            LOG.info(new ObjectMessage(logMessage));

            METRICS.putEmbeddedValue(
                    "BackChannelLogoutRequest", 1, Map.of("StatusCode", statusCode));

            if (!statusCode.equals("200")) {
                throw new PostRequestFailureException(
                        "Unable to execute POST request successfully. Status code: " + statusCode);
            }

        } catch (HttpTimeoutException e) {
            throw new HttpRequestTimeoutException(
                    format(
                            "Timeout when calling back channel logout endpoint with timeout of %d",
                            configurationService.getBackChannelLogoutCallTimeout()),
                    e);
        } catch (IOException e) {
            LOG.error("Unable to execute POST request successfully", e);
            if (e.getCause() instanceof LinkageError) {
                // In rare cases we see a linkage error within the HTTP Client
                // which fails all future requests made by the lambda
                // As a temporary measure we crash the lambda to force a restart
                LOG.error("Linkage error making AIS request, exiting with fault");
                System.exit(1);
            }
            throw e;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException(e);
        }
    }
}
