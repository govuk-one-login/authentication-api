package uk.gov.di.authentication.shared.helpers;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.openid.connect.sdk.UserInfoErrorResponse;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.services.AuthenticationService;

import java.text.ParseException;
import java.util.List;
import java.util.Map;

import static com.nimbusds.oauth2.sdk.token.BearerTokenError.INVALID_TOKEN;

public class ApiGatewayResponseHelper {

    private static final Logger LOGGER = LoggerFactory.getLogger(ApiGatewayResponseHelper.class);

    public static <T> APIGatewayProxyResponseEvent generateApiGatewayProxyResponse(
            int statusCode, T body) throws JsonProcessingException {
        return generateApiGatewayProxyResponse(
                statusCode, new ObjectMapper().writeValueAsString(body));
    }

    public static <T> APIGatewayProxyResponseEvent generateApiGatewayProxyErrorResponse(
            int statusCode, ErrorResponse errorResponse) {
        try {
            return generateApiGatewayProxyResponse(
                    statusCode, new ObjectMapper().writeValueAsString(errorResponse));
        } catch (JsonProcessingException e) {
            LOGGER.warn("Unable to generateApiGatewayProxyErrorResponse: " + e);
            return generateApiGatewayProxyResponse(500, "Internal server error");
        }
    }

    public static APIGatewayProxyResponseEvent generateApiGatewayProxyResponse(
            int statusCode, String body) {
        return generateApiGatewayProxyResponse(statusCode, body, null);
    }

    public static APIGatewayProxyResponseEvent generateApiGatewayProxyResponse(
            int statusCode, String body, Map<String, List<String>> multiValueHeaders) {
        APIGatewayProxyResponseEvent apiGatewayProxyResponseEvent =
                new APIGatewayProxyResponseEvent();
        apiGatewayProxyResponseEvent.setStatusCode(statusCode);
        apiGatewayProxyResponseEvent.setBody(body);
        if (multiValueHeaders != null) {
            apiGatewayProxyResponseEvent.setMultiValueHeaders(multiValueHeaders);
        }
        return apiGatewayProxyResponseEvent;
    }

    public static APIGatewayProxyResponseEvent validateScopesAndRetrieveUserInfo(
            String subject, AccessToken accessToken, AuthenticationService authenticationService) {
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
