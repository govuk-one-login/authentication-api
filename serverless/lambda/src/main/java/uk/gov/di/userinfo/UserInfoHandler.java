package uk.gov.di.userinfo;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.LambdaLogger;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;

import java.util.HashMap;
import java.util.Map;

public class UserInfoHandler implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Map<String, UserInfo> userInfo = new HashMap<String, UserInfo>() {{
        put("joe.bloggs@digital.cabinet-office.gov.uk", new UserInfo(new Subject()) {{
            setGivenName("Joe");
            setFamilyName("Bloggs");
            setEmailAddress("joe.bloggs@digital.cabinet-office.gov.uk");
        }});
    }};

    @Override
    public APIGatewayProxyResponseEvent handleRequest(APIGatewayProxyRequestEvent input, Context context) {
        LambdaLogger logger = context.getLogger();

        try {
            AccessToken accessToken = AccessToken.parse(input.getHeaders().get("Authorization"));
            logger.log("Access Token = " + accessToken.getValue());

            APIGatewayProxyResponseEvent apiGatewayProxyResponseEvent = new APIGatewayProxyResponseEvent();
            apiGatewayProxyResponseEvent.setStatusCode(200);
            apiGatewayProxyResponseEvent.setBody(userInfo.get("joe.bloggs@digital.cabinet-office.gov.uk").toJSONString());

            return apiGatewayProxyResponseEvent;
        } catch (ParseException e) {
            logger.log("Access Token Invalid");

            APIGatewayProxyResponseEvent apiGatewayProxyResponseEvent = new APIGatewayProxyResponseEvent();
            apiGatewayProxyResponseEvent.setStatusCode(401);
            apiGatewayProxyResponseEvent.setBody(e.getMessage());

            return apiGatewayProxyResponseEvent;
        } catch (NullPointerException e) {
            logger.log("Access Token Invalid");

            APIGatewayProxyResponseEvent apiGatewayProxyResponseEvent = new APIGatewayProxyResponseEvent();
            apiGatewayProxyResponseEvent.setStatusCode(401);
            apiGatewayProxyResponseEvent.setBody("No access token present");

            return apiGatewayProxyResponseEvent;
        }
    }
}
