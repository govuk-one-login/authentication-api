package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import uk.gov.di.authentication.frontendapi.anticorruptionlayer.AMCFailureAntiCorruption;
import uk.gov.di.authentication.frontendapi.entity.AMCAuthorizeFailureReason;
import uk.gov.di.authentication.frontendapi.entity.AMCAuthorizeRequest;
import uk.gov.di.authentication.frontendapi.entity.AMCAuthorizeResponse;
import uk.gov.di.authentication.frontendapi.entity.AMCScope;
import uk.gov.di.authentication.frontendapi.services.AMCAuthorizationService;
import uk.gov.di.authentication.frontendapi.services.JwtService;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.lambda.BaseFrontendHandler;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.AuthSessionService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.KmsConnectionService;
import uk.gov.di.authentication.shared.state.UserContext;

import java.time.Clock;

import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;

public class AMCAuthorizeHandler extends BaseFrontendHandler<AMCAuthorizeRequest> {
    private final AMCAuthorizationService amcAuthorizationService;

    public AMCAuthorizeHandler() {
        this(ConfigurationService.getInstance());
    }

    public AMCAuthorizeHandler(ConfigurationService configurationService) {
        super(AMCAuthorizeRequest.class, configurationService);
        this.amcAuthorizationService =
                new AMCAuthorizationService(
                        configurationService,
                        new NowHelper.NowClock(Clock.systemUTC()),
                        new JwtService(new KmsConnectionService(configurationService)));
    }

    @SuppressWarnings("java:S1185")
    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        return super.handleRequest(input, context);
    }

    public AMCAuthorizeHandler(
            ConfigurationService configurationService,
            AuthenticationService authenticationService,
            AuthSessionService authSessionService,
            AMCAuthorizationService amcAuthorizationService) {
        super(
                AMCAuthorizeRequest.class,
                configurationService,
                authenticationService,
                authSessionService);
        this.amcAuthorizationService = amcAuthorizationService;
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequestWithUserContext(
            APIGatewayProxyRequestEvent input,
            Context context,
            AMCAuthorizeRequest request,
            UserContext userContext) {

        AuthSessionItem authSessionItem = userContext.getAuthSession();
        var userProfile =
                authenticationService
                        .getUserProfileByEmailMaybe(authSessionItem.getEmailAddress())
                        .orElse(null);

        if (userProfile == null) {
            return generateApiGatewayProxyErrorResponse(
                    400, ErrorResponse.EMAIL_HAS_NO_USER_PROFILE);
        }

        Result<AMCAuthorizeFailureReason, String> result =
                amcAuthorizationService.buildAuthorizationUrl(
                        authSessionItem.getInternalCommonSubjectId(),
                        new AMCScope[] {AMCScope.ACCOUNT_DELETE},
                        authSessionItem,
                        userContext.getClientSessionId(),
                        userProfile.getPublicSubjectID());

        return result.fold(
                AMCFailureAntiCorruption::toApiGatewayProxyErrorResponse,
                success -> {
                    try {
                        return generateApiGatewayProxyResponse(
                                200, new AMCAuthorizeResponse(success));
                    } catch (Json.JsonException e) {
                        return generateApiGatewayProxyErrorResponse(
                                500, ErrorResponse.SERIALIZATION_ERROR);
                    }
                });
    }
}
