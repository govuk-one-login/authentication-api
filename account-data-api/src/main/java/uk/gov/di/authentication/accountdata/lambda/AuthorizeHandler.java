package uk.gov.di.authentication.accountdata.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayCustomAuthorizerEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.util.DateUtils;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.AccessTokenType;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.accountdata.entity.UnauthorizedException;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.helpers.NowHelper;

import java.util.Date;

public class AuthorizeHandler
        implements RequestHandler<APIGatewayCustomAuthorizerEvent, APIGatewayProxyResponseEvent> {
    private static final Logger LOG = LogManager.getLogger(AuthorizeHandler.class);

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayCustomAuthorizerEvent apiGatewayCustomAuthorizerEvent, Context context) {
        var token = apiGatewayCustomAuthorizerEvent.getAuthorizationToken();
        try {
            var accessToken = AccessToken.parse(token, AccessTokenType.BEARER);
            var signedAccessToken = SignedJWT.parse(accessToken.getValue());
            var claimsSet = signedAccessToken.getJWTClaimsSet();
            var accessTokenValidationResult = validateAccessTokenExpiryTime(claimsSet);

            if (accessTokenValidationResult.isFailure()) {
                throw accessTokenValidationResult.getFailure();
            }

            return new APIGatewayProxyResponseEvent().withStatusCode(200);
        } catch (ParseException | java.text.ParseException e) {
            throw new RuntimeException("TODO");
        }
    }

    private Result<UnauthorizedException, Void> validateAccessTokenExpiryTime(JWTClaimsSet claimsSet) {
        Date currentDateTime = NowHelper.now();
        if (DateUtils.isBefore(claimsSet.getExpirationTime(), currentDateTime, 0)) {
            LOG.warn(
                    "Access Token expires at: {}. CurrentDateTime is: {}",
                    claimsSet.getExpirationTime(),
                    currentDateTime);
            return Result.failure(new UnauthorizedException());
        } else {
            return Result.success(null);
        }
    }
}
