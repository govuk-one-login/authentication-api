package uk.gov.di.authentication.sharedtest.httpstub;

import org.eclipse.jetty.http.HttpURI;
import org.eclipse.jetty.io.Content;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.util.BufferUtil;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

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
        StringBuilder requestBody = new StringBuilder();
        while (true) {
            Content.Chunk chunk = request.read();
            ByteBuffer buffer = chunk.getByteBuffer();
            requestBody.append(BufferUtil.toString(buffer, StandardCharsets.UTF_8));
            if (chunk.isLast()) break;
        }
        return requestBody.toString();
    }
}
