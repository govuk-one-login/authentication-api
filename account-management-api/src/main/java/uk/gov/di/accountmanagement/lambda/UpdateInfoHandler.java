package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.accountmanagement.entity.UpdateInfoRequest;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;

import java.util.Map;

import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.RequestBodyHelper.validatePrincipal;

public class UpdateInfoHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final DynamoService dynamoService;
    private static final Logger LOGGER = LoggerFactory.getLogger(UpdateInfoHandler.class);

    public UpdateInfoHandler() {
        this.dynamoService = new DynamoService(new ConfigurationService());
    }

    public UpdateInfoHandler(DynamoService dynamoService) {
        this.dynamoService = dynamoService;
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        LOGGER.info("UpdateInfoHandler received request");
        LOGGER.info(
                "Authorizer parameters received: {}", input.getRequestContext().getAuthorizer());
        context.getClientContext();
        try {
            UpdateInfoRequest updateInfoRequest =
                    objectMapper.readValue(input.getBody(), UpdateInfoRequest.class);
            switch (updateInfoRequest.getUpdateInfoType()) {
                case EMAIL:
                    LOGGER.info("Email updateInfoType received in UpdateInfo request");
                    Subject subjectFromEmail =
                            dynamoService.getSubjectFromEmail(
                                    updateInfoRequest.getExistingProfileAttribute());
                    Map<String, Object> authorizerParams =
                            input.getRequestContext().getAuthorizer();

                    validatePrincipal(subjectFromEmail, authorizerParams);

                    dynamoService.updateEmail(
                            updateInfoRequest.getExistingProfileAttribute(),
                            updateInfoRequest.getReplacementProfileAttribute());
                    LOGGER.info("User Info has successfully been updated");
                    return generateApiGatewayProxyResponse(200, "");
            }
        } catch (JsonProcessingException | IllegalArgumentException e) {
            LOGGER.error("UpdateInfo request is missing or contains invalid parameters.", e);
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1001);
        }
        return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1019);
    }
}
