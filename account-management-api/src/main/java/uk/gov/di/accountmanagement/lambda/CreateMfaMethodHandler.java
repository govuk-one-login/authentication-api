package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.accountmanagement.entity.MFAMethod;
import uk.gov.di.accountmanagement.entity.UpdateMfaMethodRequest;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.helpers.RequestHeaderHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.SerializationService;

import static uk.gov.di.authentication.shared.domain.RequestHeaders.SESSION_ID_HEADER;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachSessionIdToLogs;

public class CreateMfaMethodHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private final Json objectMapper = SerializationService.getInstance();
    private static final Logger LOG = LogManager.getLogger(RetrieveMfaMethodsHandler.class);

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {

        try {

            String sessionId =
                    RequestHeaderHelper.getHeaderValueOrElse(
                            input.getHeaders(), SESSION_ID_HEADER, "");
            attachSessionIdToLogs(sessionId);

            UpdateMfaMethodRequest updateMfaMethod =
                    objectMapper.readValue(input.getBody(), UpdateMfaMethodRequest.class);

            MFAMethod returnMfa =
                    new MFAMethod(
                            updateMfaMethod.mfaMethod().mfaIdentifier(),
                            updateMfaMethod.mfaMethod().priorityIdentifier(),
                            updateMfaMethod.mfaMethod().mfaMethodType(),
                            updateMfaMethod.mfaMethod().endpoint(),
                            updateMfaMethod.mfaMethod().methodVerified());

            return generateApiGatewayProxyResponse(200, objectMapper.writeValueAsString(returnMfa));
        } catch (Json.JsonException | IllegalArgumentException ex) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1056);
        }
    }
}
