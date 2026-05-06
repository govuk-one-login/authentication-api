package uk.gov.di.authentication.accountdata.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;
import uk.gov.di.authentication.accountdata.services.PasskeysService;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.util.Objects;

import static uk.gov.di.authentication.accountdata.helpers.SubjectIdAuthorizerHelper.isSubjectIdAuthorized;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.segmentedFunctionCall;

public class PasskeysDeleteHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(PasskeysDeleteHandler.class);
    private final ConfigurationService configurationService;
    private final PasskeysService passkeysService;

    public PasskeysDeleteHandler() {
        this(ConfigurationService.getInstance());
    }

    public PasskeysDeleteHandler(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        this.passkeysService = new PasskeysService(configurationService);
    }

    public PasskeysDeleteHandler(
            ConfigurationService configurationService, PasskeysService passkeysService) {
        this.configurationService = configurationService;
        this.passkeysService = passkeysService;
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        ThreadContext.clearMap();
        return segmentedFunctionCall(
                "account-data-api::" + getClass().getSimpleName(),
                () -> passkeysDeleteHandler(input, context));
    }

    public APIGatewayProxyResponseEvent passkeysDeleteHandler(
            APIGatewayProxyRequestEvent input, Context context) {
        LOG.info("PasskeysDeleteHandler called");

        var publicSubjectId = input.getPathParameters().get("publicSubjectId");
        var passkeyId = input.getPathParameters().get("passkeyId");

        if (Objects.isNull(publicSubjectId)) {
            return generateApiGatewayProxyResponse(400, "");
        }

        if (!isSubjectIdAuthorized(
                input.getPathParameters().get("publicSubjectId"), input.getRequestContext())) {
            return generateApiGatewayProxyResponse(401, "");
        }

        passkeysService.deletePasskey(publicSubjectId, passkeyId);

        return generateApiGatewayProxyResponse(204, "");
    }
}
