package uk.gov.di.authentication.oidc.services;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.ObjectMessage;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse.BodyHandlers;
import java.util.Map;

import static java.net.http.HttpClient.newHttpClient;
import static java.net.http.HttpRequest.BodyPublishers.ofString;
import static uk.gov.di.authentication.shared.services.CloudwatchMetricsService.putEmbeddedValue;

public class HttpRequestService {

    private static final Logger LOG = LogManager.getLogger(HttpRequestService.class);

    public void post(URI uri, String body) {

        var request = HttpRequest.newBuilder().uri(uri).POST(ofString(body)).build();

        try {
            var response = newHttpClient().send(request, BodyHandlers.discarding());

            var logMessage =
                    Map.of(
                            "uri",
                            uri.toString(),
                            "response-code",
                            Integer.toString(response.statusCode()));

            LOG.info(new ObjectMessage(logMessage));

            putEmbeddedValue(
                    "BackChannelLogoutRequest",
                    1,
                    Map.of("StatusCode", Integer.toString(response.statusCode())));

        } catch (IOException e) {
            LOG.error("Unable to execute POST request successfully");
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
    }
}
