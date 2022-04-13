package uk.gov.di.authentication.oidc.services;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse.BodyHandlers;
import java.util.List;

import static java.net.http.HttpClient.newHttpClient;
import static java.net.http.HttpRequest.BodyPublishers.ofString;

public class HttpRequestService {

    private static final Logger LOG = LogManager.getLogger(HttpRequestService.class);

    public void post(URI uri, String body) {

        var request = HttpRequest.newBuilder().uri(uri).POST(ofString(body)).build();

        try {
            var response = newHttpClient().send(request, BodyHandlers.discarding());

            ThreadContext.put("uri", uri.toString());
            ThreadContext.put("response-code", Integer.toString(response.statusCode()));

            LOG.info("Executed POST request");

            ThreadContext.removeAll(List.of("uri", "response-code"));

        } catch (IOException e) {
            LOG.error("Unable to execute POST request successfully");
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
    }
}
