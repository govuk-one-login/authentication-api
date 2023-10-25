package uk.gov.di.authentication.sharedtest.httpstub;

import org.eclipse.jetty.http.HttpFields;
import org.eclipse.jetty.server.Request;

import java.net.URI;
import java.nio.charset.StandardCharsets;

public class RecordedRequest {
    private final URI requestURI;
    private final HttpFields headers;
    private final String method;
    private final String entity;

    public RecordedRequest(Request request) {
        this.method = request.getMethod();
        this.requestURI = request.getHttpURI().toURI();
        this.headers = request.getHeaders();
        this.entity = readEntity(request);
    }

    public String getMethod() {
        return method;
    }

    public String getEntity() {
        return entity;
    }

    public String getPath() {
        return requestURI.getPath();
    }

    public String getUrl() {
        return requestURI.toString();
    }

    public String getHeader(String name) {
        return headers.get(name);
    }

    private static String readEntity(Request request) {
        return StandardCharsets.UTF_8.decode(request.read().getByteBuffer()).toString();
    }
}
