package uk.gov.di.orchestration.sharedtest.httpstub;

import org.eclipse.jetty.http.HttpURI;
import org.eclipse.jetty.io.content.ContentSourceInputStream;
import org.eclipse.jetty.server.Request;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.stream.Collectors;

public class RecordedRequest {
    private final String requestURI;
    private final String querystring;
    private final String method;
    private final String url;
    private String entity;

    public RecordedRequest(Request request) {
        this.method = request.getMethod();
        this.requestURI = request.getHttpURI().getPath();
        this.querystring = request.getHttpURI().getQuery();
        this.entity = readEntity(request);
        HttpURI httpURI = HttpURI.build(request.getHttpURI()).query(null);
        this.url = httpURI.asString();
    }

    public String getQuerystring() {
        return querystring;
    }

    public String getMethod() {
        return method;
    }

    public String getEntity() {
        return entity;
    }

    public String getPath() {
        return requestURI;
    }

    public String getUrl() {
        return url;
    }

    private static String readEntity(Request request) {
        try (InputStream stream = new ContentSourceInputStream(request)) {
            InputStreamReader in = new InputStreamReader(stream, StandardCharsets.UTF_8);
            BufferedReader reader = new BufferedReader(in);
            return reader.lines().collect(Collectors.joining());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
