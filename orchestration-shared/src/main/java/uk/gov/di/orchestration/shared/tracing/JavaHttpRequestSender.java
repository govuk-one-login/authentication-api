package uk.gov.di.orchestration.shared.tracing;

import com.nimbusds.oauth2.sdk.http.HTTPRequestSender;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.http.ReadOnlyHTTPRequest;
import com.nimbusds.oauth2.sdk.http.ReadOnlyHTTPResponse;

import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

public class JavaHttpRequestSender implements HTTPRequestSender {
    private final HttpClient httpClient;

    public JavaHttpRequestSender(HttpClient httpClient) {
        this.httpClient = httpClient;
    }

    @Override
    public ReadOnlyHTTPResponse send(ReadOnlyHTTPRequest joseHttpRequest) throws IOException {
        try {
            var javaRequest = joseRequestToJavaRequest(joseHttpRequest);
            var javaResponse = httpClient.send(javaRequest, HttpResponse.BodyHandlers.ofString());
            return javaResponseToJoseResponse(javaResponse);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException(e);
        }
    }

    private HttpRequest joseRequestToJavaRequest(ReadOnlyHTTPRequest joseHttpRequest) {
        var requestBuilder = HttpRequest.newBuilder().uri(joseHttpRequest.getURI());

        if (joseHttpRequest.getBody() != null) {
            requestBuilder.method(
                    joseHttpRequest.getMethod().name(),
                    HttpRequest.BodyPublishers.ofString(joseHttpRequest.getBody()));
        } else {
            requestBuilder.method(
                    joseHttpRequest.getMethod().name(), HttpRequest.BodyPublishers.noBody());
        }

        for (var header : joseHttpRequest.getHeaderMap().entrySet()) {
            var key = header.getKey();
            var values = header.getValue();
            if (values != null && !values.isEmpty()) {
                for (var value : values) {
                    requestBuilder.header(key, value);
                }
            }
        }

        return requestBuilder.build();
    }

    private ReadOnlyHTTPResponse javaResponseToJoseResponse(HttpResponse<String> javaResponse) {
        var joseResponse = new HTTPResponse(javaResponse.statusCode());

        for (var header : javaResponse.headers().map().entrySet()) {
            var key = header.getKey();
            var value = header.getValue();
            if (value != null && !value.isEmpty()) {
                joseResponse.setHeader(key, value.toArray(new String[0]));
            }
        }

        joseResponse.setBody(javaResponse.body());

        return joseResponse;
    }
}
