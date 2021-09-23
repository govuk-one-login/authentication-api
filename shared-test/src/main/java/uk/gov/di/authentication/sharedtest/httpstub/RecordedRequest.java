package uk.gov.di.authentication.sharedtest.httpstub;

import org.eclipse.jetty.server.Request;

import java.io.BufferedReader;
import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class RecordedRequest {
    private final String requestURI;
    private final Map<String, List<String>> headers;
    private final String querystring;
    private final String method;
    private final String url;
    private String entity;

    public RecordedRequest(Request request) {
        this.method = request.getMethod();
        this.requestURI = request.getRequestURI();
        this.querystring = request.getQueryString();
        this.headers = getHeaders(request);
        this.entity = readEntity(request);
        this.url = request.getRequestURL().toString();
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

    public String getHeader(String name) {
        List<String> values = headers.get(name.toLowerCase());
        return values == null ? null : values.get(0);
    }

    private static String readEntity(Request request) {
        try (BufferedReader in = request.getReader()) {
            return in.lines().collect(Collectors.joining());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private static Map<String, List<String>> getHeaders(Request request) {
        return Collections.list(request.getHeaderNames()).stream()
                .collect(
                        Collectors.toUnmodifiableMap(
                                String::toLowerCase,
                                n -> List.copyOf(Collections.list(request.getHeaders(n)))));
    }
}
