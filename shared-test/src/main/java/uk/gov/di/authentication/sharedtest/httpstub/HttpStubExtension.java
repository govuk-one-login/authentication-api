package uk.gov.di.authentication.sharedtest.httpstub;

import com.fasterxml.jackson.core.JsonProcessingException;
import jakarta.ws.rs.core.UriBuilder;
import org.junit.jupiter.api.extension.AfterAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import uk.gov.di.authentication.shared.helpers.ObjectMapperFactory;

import java.net.URI;
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
        return baseUri().path(path).build();
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
                                return ObjectMapperFactory.getInstance().readValue(e, clazz);
                            } catch (JsonProcessingException ex) {
                                throw new RuntimeException(ex);
                            }
                        })
                .collect(Collectors.toList());
    }

    private UriBuilder baseUri() {
        return UriBuilder.fromUri("http://localhost").port(getHttpPort());
    }

    @Override
    public void afterAll(ExtensionContext context) throws Exception {
        httpStub.stop();
    }
}
