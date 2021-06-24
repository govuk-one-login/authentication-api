package uk.gov.di.lambdas;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import uk.gov.di.entity.Session;
import uk.gov.di.entity.VerifyCodeRequest;
import uk.gov.di.services.ConfigurationService;
import uk.gov.di.services.SessionService;

import java.util.Optional;

import static uk.gov.di.Messages.ERROR_INVALID_NOTIFICATION_TYPE;
import static uk.gov.di.Messages.ERROR_INVALID_SESSION_ID;
import static uk.gov.di.Messages.ERROR_MISSING_REQUEST_PARAMETERS;
import static uk.gov.di.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;

public class VerifyCodeHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final SessionService sessionService;
    private final ConfigurationService configService;

    public VerifyCodeHandler(SessionService sessionService, ConfigurationService configService) {
        this.sessionService = sessionService;
        this.configService = configService;
    }

    public VerifyCodeHandler() {
        this.configService = new ConfigurationService();
        this.sessionService = new SessionService(configService);
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {

        Optional<Session> session = sessionService.getSessionFromRequestHeaders(input.getHeaders());
        if (session.isEmpty()) {
            return generateApiGatewayProxyResponse(400, ERROR_INVALID_SESSION_ID);
        }

        try {
            VerifyCodeRequest codeRequest =
                    objectMapper.readValue(input.getBody(), VerifyCodeRequest.class);
            switch (codeRequest.getNotificationType()) {
                case VERIFY_EMAIL:
                    return generateApiGatewayProxyResponse(200, "OK");
            }
        } catch (JsonProcessingException e) {
            return generateApiGatewayProxyResponse(400, ERROR_MISSING_REQUEST_PARAMETERS);
        }

        return generateApiGatewayProxyResponse(400, ERROR_INVALID_NOTIFICATION_TYPE);
    }
}
