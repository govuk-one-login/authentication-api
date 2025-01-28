package uk.gov.di.orchestration.sharedtest.httpstub;

import org.apache.http.client.utils.URIBuilder;
import org.junit.jupiter.api.extension.AfterAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

import java.net.URI;
import java.net.URISyntaxException;

public class HttpStubExtension implements AfterAllCallback {

    protected final HttpStub httpStub;

    public HttpStubExtension() {
        this(null, null);
    }

    public HttpStubExtension(int port) {
        httpStub = new HttpStub(port, null, null);
        httpStub.start();
    }

    public HttpStubExtension(String keyStorePath, String keyStorePassword) {
        httpStub = new HttpStub(keyStorePath, keyStorePassword);
        httpStub.start();
    }

    public int getHttpPort() {
        return httpStub.getHttpPort();
    }

    protected void startStub() {
        httpStub.start();
    }

    public void clearRequests() {
        httpStub.clearRequests();
    }

    public void register(String path, int responseStatus) {
        httpStub.register(path, responseStatus, null, "");
    }

    public void register(String path, int responseStatus, String contentType, String responseBody) {
        httpStub.register(path, responseStatus, contentType, responseBody);
    }

    public int getCountOfRequests() {
        return httpStub.getCountOfRequests();
    }

    public URI uri(String path) {
        try {
            return baseUri().setPath(path).build();
        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        }
    }

    private URIBuilder baseUri() {
        return new URIBuilder().setHost("localhost").setScheme("http").setPort(getHttpPort());
    }

    @Override
    public void afterAll(ExtensionContext context) throws Exception {
        httpStub.stop();
    }
}
