package uk.gov.di.orchestration.local.handlers;

import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import io.javalin.http.Context;
import io.javalin.http.Handler;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.Map;
import java.util.stream.Collectors;

public class ApiGatewayLambdaHandler {
    private static final Logger LOG = LogManager.getLogger(ApiGatewayLambdaHandler.class);
    private static final LocalLambdaContext LAMBDA_CONTEXT = new LocalLambdaContext();

    private final RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent>
            lambdaHandler;

    public static Handler handlerFor(
            RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent>
                    lambdaHandler) {
        return new ApiGatewayLambdaHandler(lambdaHandler)::handle;
    }

    public ApiGatewayLambdaHandler(
            RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent>
                    lambdaHandler) {
        this.lambdaHandler = lambdaHandler;
    }

    public void handle(Context ctx) {
        try {
            APIGatewayProxyRequestEvent apiGatewayProxyRequestEvent =
                    new APIGatewayProxyRequestEvent();
            apiGatewayProxyRequestEvent.setHttpMethod(ctx.method().name());
            apiGatewayProxyRequestEvent.setBody(ctx.body());
            apiGatewayProxyRequestEvent.setHeaders(ctx.headerMap());
            apiGatewayProxyRequestEvent.setPath(ctx.path());
            apiGatewayProxyRequestEvent.setPathParameters(ctx.pathParamMap());
            // N.B. this will only take the first query param value
            apiGatewayProxyRequestEvent.setQueryStringParameters(
                    ctx.queryParamMap().entrySet().stream()
                            .collect(Collectors.toMap(
                                    Map.Entry::getKey,
                                    (e) -> e.getValue().get(0))));

            APIGatewayProxyResponseEvent responseEvent =
                    lambdaHandler.handleRequest(apiGatewayProxyRequestEvent, LAMBDA_CONTEXT);

            ctx.status(responseEvent.getStatusCode())
                    .json(responseEvent.getBody());
            responseEvent.getHeaders().forEach(ctx::header);
        } catch (RuntimeException e) {
            LOG.error("Runtime exception thrown by handler", e);
            ctx.status(500).json(Map.of("message", e.getMessage()));
        }
    }
}
