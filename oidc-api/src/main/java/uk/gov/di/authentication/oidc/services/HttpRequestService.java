package uk.gov.di.authentication.oidc.services;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.ObjectMessage;
import uk.gov.di.authentication.oidc.exceptions.PostRequestFailureException;
import uk.gov.di.orchestration.shared.services.CloudwatchMetricsService;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse.BodyHandlers;
import java.util.Map;

import static java.net.http.HttpClient.newHttpClient;
import static java.net.http.HttpRequest.BodyPublishers.ofString;

public class HttpRequestService {

    private static final Logger LOG = LogManager.getLogger(HttpRequestService.class);
    private static final CloudwatchMetricsService METRICS = new CloudwatchMetricsService();

    public void post(URI uri, String body) {

        var request =
                HttpRequest.newBuilder()
                        .uri(uri)
                        .POST(ofString(body))
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .build();

        try {
            var response = newHttpClient().send(request, BodyHandlers.discarding());

            var statusCode = Integer.toString(response.statusCode());

            var logMessage = Map.of("uri", uri.toString(), "response-code", statusCode);

            LOG.info(new ObjectMessage(logMessage));

            METRICS.putEmbeddedValue(
                    "BackChannelLogoutRequest", 1, Map.of("StatusCode", statusCode));

            if (!statusCode.equals("200")) {
                throw new PostRequestFailureException(
                        "Unable to execute POST request successfully. Status code: " + statusCode);
            }

        } catch (IOException e) {
            LOG.error("Unable to execute POST request successfully: {}", e.getMessage());
            throw new RuntimeException(e);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
    }
}
