package uk.gov.di.orchestration.identity.utils;

import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import com.nimbusds.openid.connect.sdk.UserInfoResponse;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.orchestration.identity.exceptions.IdentityCallbackException;
import uk.gov.di.orchestration.shared.entity.LevelOfConfidence;
import uk.gov.di.orchestration.shared.exceptions.UnsuccessfulCredentialResponseException;
import uk.gov.di.orchestration.shared.helpers.ConstructUriHelper;

import java.io.IOException;
import java.util.List;
import java.util.Optional;

import static uk.gov.di.orchestration.shared.entity.IdentityClaims.VOT;
import static uk.gov.di.orchestration.shared.entity.IdentityClaims.VTM;

public class IdentityCallbackUtils {
    private IdentityCallbackUtils() {}

    private static final Logger LOG = LogManager.getLogger(IdentityCallbackUtils.class);

    public static HTTPRequest createUserIdentityRequest(
            TokenResponse tokenResponse, String backendUri) {
        return new UserInfoRequest(
                        ConstructUriHelper.buildURI(backendUri, "user-identity"),
                        tokenResponse.toSuccessResponse().getTokens().getBearerAccessToken())
                .toHTTPRequest();
    }

    public static UserInfo sendUserIdentityRequest(HTTPRequest httpRequest)
            throws UnsuccessfulCredentialResponseException {
        try {
            LOG.info("Sending userinfo request");
            int count = 0;
            int maxTries = 2;
            UserInfoResponse userIdentityResponse;
            do {
                if (count > 0) LOG.warn("Retrying user identity request");
                count++;
                var httpResponse = httpRequest.send();
                userIdentityResponse = UserInfoResponse.parse(httpResponse);
                if (!httpResponse.indicatesSuccess()) {
                    LOG.warn(
                            "Unsuccessful {} response from user identity endpoint on attempt {}: {} ",
                            httpResponse.getStatusCode(),
                            count,
                            httpResponse.getBody());
                }
            } while (!userIdentityResponse.indicatesSuccess() && count < maxTries);

            if (!userIdentityResponse.indicatesSuccess()) {
                LOG.error("Response from user-identity does not indicate success");
                throw new UnsuccessfulCredentialResponseException(
                        userIdentityResponse.toErrorResponse().toString());
            } else {
                return userIdentityResponse.toSuccessResponse().getUserInfo();
            }
        } catch (ParseException e) {
            LOG.error("Error when attempting to parse HTTPResponse to UserInfoResponse");
            throw new UnsuccessfulCredentialResponseException(
                    "Error when attempting to parse http response to UserInfoResponse");
        } catch (IOException e) {
            LOG.error("Error when attempting to call user-identity endpoint", e);
            throw new RuntimeException(e);
        }
    }

    public static Optional<ErrorObject> validateUserIdentityResponse(
            UserInfo userIdentityUserInfo,
            List<LevelOfConfidence> requestedLoCs,
            String trustmarkURL)
            throws IdentityCallbackException {
        LOG.info("Validating userinfo response");
        for (LevelOfConfidence loc : requestedLoCs) {
            if (loc.getValue().equals(userIdentityUserInfo.getClaim(VOT.getValue()))) {

                if (!trustmarkURL.equals(userIdentityUserInfo.getClaim(VTM.getValue()))) {
                    LOG.warn("VTM does not contain expected trustmark URL");
                    throw new IdentityCallbackException("Identity trustmark is invalid");
                }
                return Optional.empty();
            }
        }
        LOG.warn("User identity response missing vot or vot not in vtr list.");
        return Optional.of(OAuth2Error.ACCESS_DENIED);
    }
}
