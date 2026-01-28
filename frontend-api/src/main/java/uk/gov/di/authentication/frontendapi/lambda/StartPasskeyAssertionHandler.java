package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.frontendapi.entity.StartPasskeyAssertionRequest;
import uk.gov.di.authentication.frontendapi.services.webauthn.DefaultPasskeyJsonParser;
import uk.gov.di.authentication.frontendapi.services.webauthn.PasskeyAssertionService;
import uk.gov.di.authentication.frontendapi.services.webauthn.RelyingPartyProvider;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.lambda.BaseFrontendHandler;
import uk.gov.di.authentication.shared.services.AuthSessionService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.state.UserContext;

import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;

public class StartPasskeyAssertionHandler extends BaseFrontendHandler<StartPasskeyAssertionRequest>
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(StartPasskeyAssertionHandler.class);
    private final PasskeyAssertionService passkeyAssertionService;

    public StartPasskeyAssertionHandler() {
        this(ConfigurationService.getInstance());
    }

    public StartPasskeyAssertionHandler(
            ConfigurationService configurationService,
            AuthenticationService authenticationService,
            AuthSessionService authSessionService,
            PasskeyAssertionService passkeyAssertionService) {
        super(
                StartPasskeyAssertionRequest.class,
                configurationService,
                authenticationService,
                authSessionService);
        this.passkeyAssertionService = passkeyAssertionService;
    }

    public StartPasskeyAssertionHandler(ConfigurationService configurationService) {
        super(StartPasskeyAssertionRequest.class, configurationService);
        this.passkeyAssertionService =
                new PasskeyAssertionService(
                        RelyingPartyProvider.provide(configurationService),
                        new DefaultPasskeyJsonParser());
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
            StartPasskeyAssertionRequest request,
            UserContext userContext) {
        LOG.info("StartPasskeyAssertionHandler called");
        var emailAddress = userContext.getAuthSession().getEmailAddress();
        if (emailAddress == null || emailAddress.isEmpty()) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.EMAIL_ADDRESS_EMPTY);
        }
        var userProfile = authenticationService.getUserProfileByEmailMaybe(emailAddress);
        if (userProfile.isEmpty()) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.USER_NOT_FOUND);
        }
        var subjectId = userProfile.get().getSubjectID();

        var assertionRequest = passkeyAssertionService.startAssertion(subjectId);

        String credentialsJson;
        String assertionRequestJsonToStore;
        try {
            credentialsJson = assertionRequest.toCredentialsGetJson();
            assertionRequestJsonToStore = assertionRequest.toJson();
        } catch (JsonProcessingException e) {
            LOG.error("Error serializing assertion request", e);
            return generateApiGatewayProxyErrorResponse(
                    500, ErrorResponse.UNEXPECTED_INTERNAL_API_ERROR);
        }

        authSessionService.updateSession(
                userContext
                        .getAuthSession()
                        .withPasskeyAssertionRequest(assertionRequestJsonToStore));
        return generateApiGatewayProxyResponse(200, credentialsJson);
    }
}
