package uk.gov.di.orchestration.sharedtest.pact;

import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;

import java.util.HashMap;
import java.util.LinkedList;
import java.util.Map;
import java.util.regex.Pattern;

import static java.text.MessageFormat.format;

public class LambdaHandlerConfig {

    private static final String PARAM_NAME_KEY = "ParamName";
    private static final String PATH_PARAM_PATTERN =
            "\\{(?<" + PARAM_NAME_KEY + ">[a-zA-Z][a-zA-Z0-9]*)}";
    private static final String PATH_ELEM_PATTERN = "([a-zA-Z0-9]+)";
    private static final Pattern HTTP_METHOD_REGEX = Pattern.compile("^(GET|POST|PUT|DELETE)$");
    private static final Pattern PATH_REGEX =
            Pattern.compile("^((/(" + PATH_ELEM_PATTERN + "|" + PATH_PARAM_PATTERN + "))*/?)$");
    private static final Pattern PATH_PARAM_REGEX = Pattern.compile(PATH_PARAM_PATTERN);

    private final String httpMethod;
    private final Pattern pathRegex;
    private final LinkedList<String> pathRegexGroupNames;
    private final RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> handler;

    /**
     * @param path use curley braces to specify path parameters e.g.
     *     /root/path/{someParameter}/{anotherParameter}
     */
    public LambdaHandlerConfig(
            String httpMethod,
            String path,
            RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> handler) {
        if (!HTTP_METHOD_REGEX.matcher(httpMethod).matches()) {
            throw new IllegalArgumentException(format("Unknown HTTP method \"{0}\".", httpMethod));
        }

        if (!PATH_REGEX.matcher(path).matches()) {
            throw new IllegalArgumentException(format("Badly formatted path \"{0}\".", path));
        }

        var pathRegexGroupNames = new LinkedList<String>();
        var pathPattern = new StringBuilder();
        pathPattern.append("^");
        var pathElems = path.startsWith("/") ? path.substring(1).split("/") : path.split("/");
        for (var pathElem : pathElems) {
            pathPattern.append("/");
            var paramMatch = PATH_PARAM_REGEX.matcher(pathElem);
            if (paramMatch.matches()) {
                pathPattern.append(PATH_ELEM_PATTERN);
                var paramName = paramMatch.group(PARAM_NAME_KEY);
                if (pathRegexGroupNames.contains(paramName)) {
                    throw new IllegalArgumentException(
                            format(
                                    "Duplicate path param \"{0}\" in path \"{1}\"",
                                    paramName, path));
                }

                pathRegexGroupNames.add(paramName);
            } else {
                pathPattern.append(pathElem);
            }
        }

        pathPattern.append("/?$");

        this.httpMethod = httpMethod;
        this.pathRegex = Pattern.compile(pathPattern.toString());
        this.pathRegexGroupNames = pathRegexGroupNames;
        this.handler = handler;
    }

    public boolean handles(String httpMethod, String path) {
        return this.httpMethod.equals(httpMethod) && pathRegex.matcher(path).matches();
    }

    public RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> getHandler() {
        return handler;
    }

    public Map<String, String> getPathParameters(String path) {
        var pathParamMap = new HashMap<String, String>();
        var matcher = pathRegex.matcher(path);
        if (matcher.matches()) {
            var matchCount = matcher.groupCount();
            for (int i = 0; i < matchCount; i++) {
                var paramName = pathRegexGroupNames.get(i);
                var paramValue = matcher.group(i + 1);
                pathParamMap.put(paramName, paramValue);
            }
        }

        return pathParamMap;
    }
}
