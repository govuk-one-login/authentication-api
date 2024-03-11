package uk.gov.di.orchestration.shared.pact;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import org.apache.commons.io.IOUtils;
import org.mockito.Mockito;

import java.io.IOException;
import java.io.OutputStream;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

import static java.text.MessageFormat.format;
import static java.util.Objects.isNull;

public class LambdaHandlerWrapper implements HttpHandler {
    private final List<LambdaHandlerWrapperConfig> config;

    public LambdaHandlerWrapper(List<LambdaHandlerWrapperConfig> config) {
        this.config = config;
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        try {
            var handlerConfig = findHandler(exchange);
            var response = translateRequest(exchange, handlerConfig);
            translateResponse(exchange, response);
        } catch (Exception e) {
            String error = "Some error occurred";
            exchange.sendResponseHeaders(500, error.length());
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(error.getBytes(StandardCharsets.UTF_8));
            }
        }
    }

    private LambdaHandlerWrapperConfig findHandler(HttpExchange request) {
        var path = request.getRequestURI().getPath();
        var httpMethod = request.getRequestMethod();

        for (var handlerConfig : config) {
            if (handlerConfig.handles(
                    request.getRequestMethod(), request.getRequestURI().getPath())) {
                return handlerConfig;
            }
        }

        throw new IllegalArgumentException(
                format("No configuration to handle \"{0}\" \"{1}\".", httpMethod, path));
    }

    private APIGatewayProxyResponseEvent translateRequest(
            HttpExchange exchange, LambdaHandlerWrapperConfig handlerConfig) throws IOException {
        var requestId = UUID.randomUUID().toString();

        var requestContext =
                new APIGatewayProxyRequestEvent.ProxyRequestContext().withRequestId(requestId);

        var httpMethod = exchange.getRequestMethod();

        var multiValueHeaders = exchange.getRequestHeaders();
        var headers = multiValueToSingleValue(multiValueHeaders);

        var multiValueQueryStringParameters =
                getMultiValueQueryParams(exchange.getRequestURI().getQuery());
        var queryParameters = multiValueToSingleValue(multiValueQueryStringParameters);

        var path = exchange.getRequestURI().getPath();
        var pathParameters = handlerConfig.getPathParameters(path);

        var requestBody = IOUtils.toString(exchange.getRequestBody(), StandardCharsets.UTF_8);

        var request =
                new APIGatewayProxyRequestEvent()
                        .withRequestContext(requestContext)
                        .withPath(path)
                        .withHttpMethod(httpMethod)
                        .withHeaders(headers)
                        .withMultiValueHeaders(multiValueHeaders)
                        .withQueryStringParameters(queryParameters)
                        .withMultiValueQueryStringParameters(multiValueQueryStringParameters)
                        .withPathParameters(pathParameters)
                        .withBody(requestBody);

        var handler = handlerConfig.getHandler();
        var context = Mockito.mock(Context.class);
        return handler.handleRequest(request, context);
    }

    private static Map<String, String> multiValueToSingleValue(
            Map<String, List<String>> multiValueMap) {
        return multiValueMap.entrySet().stream()
                .filter(x -> x.getValue().size() == 1)
                .collect(Collectors.toMap(Map.Entry::getKey, x -> x.getValue().get(0)));
    }

    public static Map<String, List<String>> getMultiValueQueryParams(String queryString) {
        if (isNull(queryString)) {
            return Collections.emptyMap();
        }

        Map<String, List<String>> multiValueMap = new HashMap<>();
        var pairs = Arrays.stream(queryString.split("&", -1)).map(q -> q.split("=", -1)).toList();
        for (var pair : pairs) {
            if (pair.length != 2) {
                return Collections.emptyMap();
            }

            var queryKey = URLDecoder.decode(pair[0], StandardCharsets.UTF_8);
            var queryValue = URLDecoder.decode(pair[1], StandardCharsets.UTF_8);
            multiValueMap.computeIfAbsent(queryKey, key -> new LinkedList<>());
            multiValueMap.get(queryKey).add(queryValue);
        }

        return multiValueMap;
    }

    private void translateResponse(HttpExchange exchange, APIGatewayProxyResponseEvent response)
            throws IOException {
        Integer statusCode = response.getStatusCode();

        Headers serverResponseHeaders = exchange.getResponseHeaders();
        response.getHeaders().forEach(serverResponseHeaders::set);

        if (!response.getBody().isEmpty()) {
            serverResponseHeaders.computeIfAbsent(
                    "Content-Type", key -> List.of("application/json"));
            String body = response.getBody();
            exchange.sendResponseHeaders(statusCode, body.length());
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(body.getBytes(StandardCharsets.UTF_8));
            }
        }
    }
}
