package uk.gov.di.orchestration.sharedtest.pact;

import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.List;

public class LambdaHttpServer {

    private final HttpServer server;

    public LambdaHttpServer(String host, int port, List<LambdaHandlerConfig> config)
            throws IOException {
        InetSocketAddress sockAddr = new InetSocketAddress(host, port);
        this.server = HttpServer.create(sockAddr, 0);
        this.server.createContext("/", new LambdaHandlerWrapper(config));
    }

    public void start() {
        server.start();
    }

    public void stop() {
        server.stop(0);
    }
}
