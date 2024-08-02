package uk.gov.di.authentication.sharedtest.httpstub;

import org.apache.http.client.utils.URIBuilder;
import org.junit.jupiter.api.extension.AfterAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.SerializationService;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.stream.Collectors;

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

    public HttpStubExtension(
            String keyStorePath,
            String keyStorePassword,
            String trustStorePath,
            String trustStorePassword) {
        httpStub = new HttpStub(keyStorePath, keyStorePassword, trustStorePath, trustStorePassword);
        httpStub.start();
    }

    public HttpStubExtension(
            boolean needSsl,
            String keyStorePath,
            String keyStorePassword,
            String trustStorePath,
            String trustStorePassword) {
        httpStub =
                new HttpStub(
                        needSsl,
                        keyStorePath,
                        keyStorePassword,
                        trustStorePath,
                        trustStorePassword);
        httpStub.start();
    }

    public int getHttpPort() {
        return httpStub.getHttpPort();
    }

    public int getHttpsPort() {
        return httpStub.getHttpsPort();
    }

    public void startStub() {
        httpStub.start();
    }

    public void reset() {
        httpStub.reset();
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

    public int getCountOfRequestsTo(final String path) {
        return httpStub.getCountOfRequestsTo(path);
    }

    public int getCountOfRequests() {
        return httpStub.getCountOfRequests();
    }

    public RecordedRequest getLastRequest() {
        return httpStub.getLastRequest();
    }

    public URI uri(String path) {
        try {
            return baseUri().setPath(path).build();
        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        }
    }

    public List<RecordedRequest> getRecordedRequests() {
        return httpStub.getRecordedRequests();
    }

    public <T> List<T> getRecordedRequests(Class<T> clazz) {
        return httpStub.getRecordedRequests().stream()
                .map(RecordedRequest::getEntity)
                .map(
                        e -> {
                            try {
                                return SerializationService.getInstance().readValue(e, clazz);
                            } catch (Json.JsonException ex) {
                                throw new RuntimeException(ex);
                            }
                        })
                .collect(Collectors.toList());
    }

    private URIBuilder baseUri() {
        return new URIBuilder().setHost("localhost").setScheme("http").setPort(getHttpPort());
    }

    @Override
    public void afterAll(ExtensionContext context) throws Exception {
        httpStub.stop();
    }
}
