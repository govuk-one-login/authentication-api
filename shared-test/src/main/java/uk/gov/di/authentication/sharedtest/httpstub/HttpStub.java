package uk.gov.di.authentication.sharedtest.httpstub;

import org.eclipse.jetty.server.Handler;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Response;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.util.Callback;
import org.eclipse.jetty.util.ssl.SslContextFactory;

import java.io.File;
import java.nio.ByteBuffer;
import java.security.KeyStore;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.stream.Collectors;

import static uk.gov.di.authentication.sharedtest.exceptions.Unchecked.unchecked;

class HttpStub {

    private static final int RANDOM_PORT = 0;
    private Server server;
    private ConcurrentMap<String, RegisteredResponse> registeredResponses =
            new ConcurrentHashMap<>();
    private List<RecordedRequest> recordedRequests = new CopyOnWriteArrayList<>();

    public HttpStub(String keyStorePath, String keyStorePassword) {
        this(RANDOM_PORT, keyStorePath, keyStorePassword);
    }

    public HttpStub(int port, String keyStorePath, String keyStorePassword) {
        this(port, false, keyStorePath, keyStorePassword, null, null);
    }

    public HttpStub(
            String keyStorePath,
            String keyStorePassword,
            String trustStorePath,
            String trustStorePassword) {
        this(
                RANDOM_PORT,
                false,
                keyStorePath,
                keyStorePassword,
                trustStorePath,
                trustStorePassword);
    }

    public HttpStub(
            boolean needSSL,
            String keyStorePath,
            String keyStorePassword,
            String trustStorePath,
            String trustStorePassword) {
        this(
                RANDOM_PORT,
                needSSL,
                keyStorePath,
                keyStorePassword,
                trustStorePath,
                trustStorePassword);
    }

    private HttpStub(
            int port,
            boolean needSSL,
            String keyStorePath,
            String keyStorePassword,
            String trustStorePath,
            String trustStorePassword) {
        server = new Server(port);
        if (keyStorePath != null) {
            File file = new File(keyStorePath);
            char[] password = keyStorePassword.toCharArray();
            KeyStore keyStore = unchecked(() -> KeyStore.getInstance(file, password));
            SslContextFactory.Server sslContextFactory = new SslContextFactory.Server();
            if (trustStorePath != null) {

                KeyStore trustStore =
                        unchecked(
                                () ->
                                        KeyStore.getInstance(
                                                new File(trustStorePath),
                                                trustStorePassword.toCharArray()));
                sslContextFactory.setTrustStore(trustStore);
                sslContextFactory.setTrustStorePassword(trustStorePassword);
            } else {
                sslContextFactory.setTrustStore(keyStore);
                sslContextFactory.setTrustStorePassword(keyStorePassword);
            }

            sslContextFactory.setNeedClientAuth(needSSL);
            sslContextFactory.setKeyStore(keyStore);
            sslContextFactory.setKeyStorePassword(keyStorePassword);

            ServerConnector serverConnector = new ServerConnector(server, sslContextFactory);

            server.addConnector(serverConnector);
        }
        server.setHandler(new TestHandler());
    }

    public void start() {
        try {
            server.start();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public void stop() throws Exception {
        server.setStopTimeout(0);
        server.stop();
    }

    public int getHttpPort() {
        return ((ServerConnector) server.getConnectors()[0]).getLocalPort();
    }

    public int getHttpsPort() {
        return ((ServerConnector) server.getConnectors()[1]).getLocalPort();
    }

    public void reset() {
        registeredResponses.clear();
        clearRequests();
    }

    public void clearRequests() {
        recordedRequests.clear();
    }

    public void register(String path, int responseStatus, String contentType, String responseBody) {
        if (path.isBlank()) path = "/";
        registeredResponses.put(
                path, new RegisteredResponse(responseStatus, contentType, responseBody));
    }

    public int getCountOfRequestsTo(final String path) {
        return recordedRequests.stream()
                .filter(input -> input.getPath().equals(path))
                .collect(Collectors.toList())
                .size();
    }

    public RecordedRequest getLastRequest() {
        return recordedRequests.get(recordedRequests.size() - 1);
    }

    public int getCountOfRequests() {
        return recordedRequests.size();
    }

    public List<RecordedRequest> getRecordedRequests() {
        return recordedRequests;
    }

    private class TestHandler extends Handler.Abstract {

        @Override
        public boolean handle(Request request, Response response, Callback callback)
                throws Exception {
            recordedRequests.add(new RecordedRequest(request));
            RegisteredResponse registeredResponse = registeredResponses.get(request.getHttpURI().getPath());
            if (registeredResponse != null) {
                response.setStatus(registeredResponse.getStatus());
                if (registeredResponse.getContentType() != null) {
                    response.getHeaders().add("Content-Type", registeredResponse.getContentType());
                }
                response.write(
                        true, ByteBuffer.wrap(registeredResponse.getBody().getBytes()), callback);
            }
            return true;
        }
    }
}
