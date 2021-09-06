package uk.gov.di.accountmanagement.helpers.httpstub;

import jakarta.ws.rs.core.UriBuilder;
import org.junit.jupiter.api.extension.AfterAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

import java.net.URI;

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

    public static HttpStubExtension httpStubExtensionWithValidSslCert() {
        return new HttpStubExtension("deploy/keys/server_auth.ks", "puppet");
    }

    public static HttpStubExtension httpStubExtensionWithClientAuth() {
        return new HttpStubExtension(
                true,
                "deploy/keys/server_auth.ks",
                "puppet",
                "deploy/keys/server_auth.ks",
                "puppet");
    }

    public static HttpStubExtension httpStubExtensionWithInvalidSslCert() {
        return new HttpStubExtension("deploy/keys/invalid_server_ssl_auth.ks", "puppet");
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

    private UriBuilder baseUri() {
        return UriBuilder.fromUri("http://localhost").port(getHttpPort());
    }

    @Override
    public void afterAll(ExtensionContext context) throws Exception {
        httpStub.stop();
    }
}
