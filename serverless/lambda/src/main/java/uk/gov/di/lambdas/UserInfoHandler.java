package uk.gov.di.lambdas;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.openid.connect.sdk.UserInfoErrorResponse;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.entity.UserProfile;
import uk.gov.di.services.AuthenticationService;
import uk.gov.di.services.ConfigurationService;
import uk.gov.di.services.DynamoService;
import uk.gov.di.services.RedisConnectionService;
import uk.gov.di.services.TokenService;

import java.text.ParseException;
import java.util.List;
import java.util.Optional;

import static com.nimbusds.oauth2.sdk.token.BearerTokenError.INVALID_TOKEN;
import static com.nimbusds.oauth2.sdk.token.BearerTokenError.MISSING_TOKEN;
import static java.lang.String.format;
import static uk.gov.di.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;

public class UserInfoHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOGGER = LoggerFactory.getLogger(UserInfoHandler.class);

    private final TokenService tokenService;
    private final ConfigurationService configurationService;
    private final AuthenticationService authenticationService;

    public UserInfoHandler(
            TokenService tokenService,
            ConfigurationService configurationService,
            AuthenticationService authenticationService) {
        this.tokenService = tokenService;
        this.configurationService = configurationService;
        this.authenticationService = authenticationService;
    }

    public UserInfoHandler() {
        configurationService = new ConfigurationService();
        tokenService =
                new TokenService(
                        configurationService, new RedisConnectionService(configurationService));
        authenticationService =
                new DynamoService(
                        configurationService.getAwsRegion(),
                        configurationService.getEnvironment(),
                        configurationService.getDynamoEndpointUri());
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        if (input.getHeaders() == null
                || !input.getHeaders().containsKey("Authorization")
                || input.getHeaders().get("Authorization").isEmpty()) {
            LOGGER.error("AccessToken is missing from request");
            return generateApiGatewayProxyResponse(
                    401,
                    "",
                    new UserInfoErrorResponse(MISSING_TOKEN).toHTTPResponse().getHeaderMap());
        }
        AccessToken accessToken;
        try {
            accessToken = AccessToken.parse(input.getHeaders().get("Authorization"));
        } catch (Exception e) {
            LOGGER.error(
                    format(
                            "Unable to parse AccessToken with headers: %s.\n\n Exception thrown: %s",
                            input.getHeaders(), e));
            return generateApiGatewayProxyResponse(
                    401,
                    "",
                    new UserInfoErrorResponse(INVALID_TOKEN).toHTTPResponse().getHeaderMap());
        }
        Optional<String> subjectFromAccessToken =
                tokenService.getSubjectWithAccessToken(accessToken);

        return subjectFromAccessToken
                .map(t -> validateScopesAndRetrieveUserInfo(t, accessToken))
                .orElse(
                        generateApiGatewayProxyResponse(
                                401,
                                "",
                                new UserInfoErrorResponse(INVALID_TOKEN)
                                        .toHTTPResponse()
                                        .getHeaderMap()));
    }

    private APIGatewayProxyResponseEvent validateScopesAndRetrieveUserInfo(
            String subject, AccessToken accessToken) {
        UserProfile userProfile = authenticationService.getUserProfileFromSubject(subject);
        List<String> scopes;
        try {
            SignedJWT signedAccessToken = SignedJWT.parse(accessToken.getValue());
            scopes = (List<String>) signedAccessToken.getJWTClaimsSet().getClaim("scope");
        } catch (ParseException e) {
            return generateApiGatewayProxyResponse(
                    401,
                    "",
                    new UserInfoErrorResponse(INVALID_TOKEN).toHTTPResponse().getHeaderMap());
        }
        UserInfo userInfo = new UserInfo(new Subject(subject));
        if (scopes.contains("email")) {
            userInfo.setEmailAddress(userProfile.getEmail());
            userInfo.setEmailVerified(userProfile.isEmailVerified());
        }
        if (scopes.contains("phone")) {
            userInfo.setPhoneNumber(userProfile.getPhoneNumber());
            userInfo.setPhoneNumberVerified(userProfile.isPhoneNumberVerified());
        }
        return generateApiGatewayProxyResponse(200, userInfo.toJSONString());
    }
}
