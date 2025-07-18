package uk.gov.di.authentication.local.handlers;

import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import io.javalin.http.Context;
import io.javalin.http.Handler;

public class ApiGatewayLambdaHandler {
    private static final LocalLambdaContext LAMBDA_CONTEXT = new LocalLambdaContext();

    private final RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> lambdaHandler;

    public static Handler handlerFor(
            RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> lambdaHandler
    ) {
        return new ApiGatewayLambdaHandler(lambdaHandler)::handle;
    }

    public ApiGatewayLambdaHandler(
            RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> lambdaHandler
    ) {
        this.lambdaHandler = lambdaHandler;
    }

    public void handle(Context ctx) {
        APIGatewayProxyRequestEvent apiGatewayProxyRequestEvent = new APIGatewayProxyRequestEvent();
        apiGatewayProxyRequestEvent.setBody(ctx.body());
        apiGatewayProxyRequestEvent.setHeaders(ctx.headerMap());
        apiGatewayProxyRequestEvent.setPath(ctx.path());

        APIGatewayProxyResponseEvent responseEvent =
                lambdaHandler.handleRequest(apiGatewayProxyRequestEvent, LAMBDA_CONTEXT);

        ctx.status(responseEvent.getStatusCode()).json(responseEvent.getBody());
    }
}
