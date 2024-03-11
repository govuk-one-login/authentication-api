package uk.gov.di.orchestration.shared.pact;

import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.LinkedList;
import java.util.List;

public class LambdaHttpServer {

    private final HttpServer server;

    private LambdaHttpServer(String host, int port, List<LambdaHandlerWrapperConfig> config)
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

    public static LambdaHttpServerBuilderPort builder() {
        return new LambdaHttpServerBuilder() {
            private String host;
            private int port;
            private final List<LambdaHandlerWrapperConfig> config = new LinkedList<>();

            @Override
            public LambdaHttpServer build() throws IOException {
                return new LambdaHttpServer(host, port, config);
            }

            @Override
            public LambdaHttpServerBuilderHandleOrBuild handle(
                    String httpMethod,
                    String path,
                    RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent>
                            handler) {
                this.config.add(new LambdaHandlerWrapperConfig(httpMethod, path, handler));
                return this;
            }

            @Override
            public LambdaHttpServerBuilderHandle atAddress(String host, int port) {
                this.host = host;
                this.port = port;
                return this;
            }
        };
    }

    public interface LambdaHttpServerBuilderPort {
        LambdaHttpServerBuilderHandle atAddress(String host, int port);
    }

    public interface LambdaHttpServerBuilderHandle {
        /**
         * @param path use curley braces to specify path parameters e.g.
         *     /root/path/{someParameter}/{anotherParameter}
         */
        LambdaHttpServerBuilderHandleOrBuild handle(
                String httpMethod,
                String path,
                RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> handler);
    }

    public interface LambdaHttpServerBuilderHandleOrBuild extends LambdaHttpServerBuilderHandle {
        LambdaHttpServer build() throws IOException;
    }

    private interface LambdaHttpServerBuilder
            extends LambdaHttpServerBuilderPort, LambdaHttpServerBuilderHandleOrBuild {}
}
