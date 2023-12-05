package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.frontendapi.entity.AccountInterventionsRequest;
import uk.gov.di.authentication.frontendapi.entity.AccountInterventionsResponse;
import uk.gov.di.authentication.frontendapi.services.AccountInterventionsService;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.exceptions.UnsuccessfulAccountInterventionsResponseException;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.lambda.BaseFrontendHandler;
import uk.gov.di.authentication.shared.serialization.Json.JsonException;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.shared.state.UserContext;

import static com.nimbusds.oauth2.sdk.http.HTTPRequest.Method.GET;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.ConstructUriHelper.buildURI;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.LogFieldName.AWS_REQUEST_ID;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachLogFieldToLogs;

public class AccountInterventionsHandler extends BaseFrontendHandler<AccountInterventionsRequest> {
    private static final Logger LOG = LogManager.getLogger(AccountInterventionsHandler.class);
    private final AccountInterventionsService accountInterventionsService;

    protected AccountInterventionsHandler(
            ConfigurationService configurationService,
            SessionService sessionService,
            ClientSessionService clientSessionService,
            ClientService clientService,
            AuthenticationService authenticationService,
            AccountInterventionsService accountInterventionsService) {
        super(
                AccountInterventionsRequest.class,
                configurationService,
                sessionService,
                clientSessionService,
                clientService,
                authenticationService);
        this.accountInterventionsService = accountInterventionsService;
    }

    public AccountInterventionsHandler(ConfigurationService configurationService) {
        super(AccountInterventionsRequest.class, configurationService);
        accountInterventionsService = new AccountInterventionsService();
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        return super.handleRequest(input, context);
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequestWithUserContext(
            APIGatewayProxyRequestEvent input,
            Context context,
            AccountInterventionsRequest request,
            UserContext userContext) {
        attachLogFieldToLogs(AWS_REQUEST_ID, context.getAwsRequestId());
        LOG.info("Request received to the AccountInterventionsHandler");

        var userProfile = authenticationService.getUserProfileByEmailMaybe(request.email());
        if (userProfile.isEmpty()) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1049);
        }

        try {
            var internalPairwiseId =
                    ClientSubjectHelper.getSubjectWithSectorIdentifier(
                                    userProfile.get(),
                                    configurationService.getInternalSectorUri(),
                                    authenticationService)
                            .getValue();
            var accountInterventionsEndpoint =
                    configurationService.getAccountInterventionServiceURI().toString();
            var accountInterventionsURI =
                    buildURI(accountInterventionsEndpoint, "/v1/ais/" + internalPairwiseId);
            var accountInterventionsInboundRequest = new HTTPRequest(GET, accountInterventionsURI);
            var accountInterventionsInboundResponse =
                    accountInterventionsService.sendAccountInterventionsOutboundRequest(
                            accountInterventionsInboundRequest);
            LOG.info("Generating Account Interventions outbound response for frontend");
            var accountInterventionsResponse =
                    new AccountInterventionsResponse(
                            accountInterventionsInboundResponse.state().resetPassword(),
                            accountInterventionsInboundResponse.state().blocked(),
                            accountInterventionsInboundResponse.state().suspended());
            return generateApiGatewayProxyResponse(200, accountInterventionsResponse, true);
        } catch (UnsuccessfulAccountInterventionsResponseException e) {
            LOG.debug(
                    "Error in Account Interventions response HttpCode: {}, ErrorMessage: {}.",
                    e.getHttpCode(),
                    e.getMessage());
            if (e.getHttpCode() == 429) {
                return generateApiGatewayProxyErrorResponse(429, ErrorResponse.ERROR_1051);
            }
            if (e.getHttpCode() == 500) {
                return generateApiGatewayProxyErrorResponse(500, ErrorResponse.ERROR_1052);
            }
            if (e.getHttpCode() == 502) {
                return generateApiGatewayProxyErrorResponse(502, ErrorResponse.ERROR_1053);
            }
            if (e.getHttpCode() == 504) {
                return generateApiGatewayProxyErrorResponse(504, ErrorResponse.ERROR_1054);
            }
            return generateApiGatewayProxyErrorResponse(e.getHttpCode(), ErrorResponse.ERROR_1055);
        } catch (JsonException e) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.ERROR_1001);
        }
    }
}
