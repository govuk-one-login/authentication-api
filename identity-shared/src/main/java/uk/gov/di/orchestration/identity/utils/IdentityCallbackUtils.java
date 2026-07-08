package uk.gov.di.orchestration.identity.utils;

import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import com.nimbusds.openid.connect.sdk.UserInfoResponse;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.orchestration.identity.exceptions.IdentityResponseValidationError;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.entity.VectorOfTrust;
import uk.gov.di.orchestration.shared.exceptions.IdentityCallbackException;
import uk.gov.di.orchestration.shared.exceptions.UnsuccessfulCredentialResponseException;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static java.lang.String.format;
import static uk.gov.di.orchestration.shared.entity.IdentityClaims.VOT;
import static uk.gov.di.orchestration.shared.entity.IdentityClaims.VTM;
import static uk.gov.di.orchestration.shared.entity.ValidClaims.RETURN_CODE;

public class IdentityCallbackUtils {
    private static final Logger LOG = LogManager.getLogger(IdentityCallbackUtils.class);

    public Optional<IdentityResponseValidationError> validateResponse(
            Map<String, String> queryParams, Optional<String> stateFromDynamo) {
        if (queryParams == null || queryParams.isEmpty()) {
            LOG.warn("No Query parameters in Authorisation response");
            return Optional.of(
                    new IdentityResponseValidationError(
                            OAuth2Error.INVALID_REQUEST_CODE, "No query parameters present"));
        }
        if (!queryParams.containsKey("state") || queryParams.get("state").isEmpty()) {
            LOG.warn("No state param in Authorisation response");
            return Optional.of(
                    new IdentityResponseValidationError(
                            OAuth2Error.INVALID_REQUEST_CODE,
                            "No state param present in Authorisation response"));
        }
        if (!isStateValid(stateFromDynamo, queryParams.get("state"))) {
            return Optional.of(
                    new IdentityResponseValidationError(
                            OAuth2Error.INVALID_REQUEST_CODE,
                            "Invalid state param present in Authorisation response"));
        }
        if (!queryParams.containsKey("code") || queryParams.get("code").isEmpty()) {
            LOG.warn("No code param in Authorisation response");
            return Optional.of(
                    new IdentityResponseValidationError(
                            OAuth2Error.INVALID_REQUEST_CODE,
                            "No code param present in Authorisation response"));
        }
        return Optional.empty();
    }

    private boolean isStateValid(Optional<String> stateFromDynamo, String responseState) {
        if (stateFromDynamo.isEmpty()) {
            LOG.info("No state found in Dynamo");
            return false;
        }

        State storedState = new State(stateFromDynamo.get());
        LOG.info(
                "Response state: {} and Stored state: {}. Are equal: {}",
                responseState,
                storedState.getValue(),
                responseState.equals(storedState.getValue()));
        return responseState.equals(storedState.getValue());
    }

    public static UserInfo sendUserIdentityRequest(UserInfoRequest userInfoRequest)
            throws UnsuccessfulCredentialResponseException {
        try {
            LOG.info("Sending IPV userinfo request");
            int count = 0;
            int maxTries = 2;
            UserInfoResponse userIdentityResponse;
            do {
                if (count > 0) LOG.warn("Retrying IPV user identity request");
                count++;
                var httpResponse = userInfoRequest.toHTTPRequest().send();
                userIdentityResponse = UserInfoResponse.parse(httpResponse);
                if (!httpResponse.indicatesSuccess()) {
                    LOG.warn(
                            format(
                                    "Unsuccessful %s response from IPV user identity endpoint on attempt %d: %s ",
                                    httpResponse.getStatusCode(), count, httpResponse.getBody()));
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
            LOG.error("Error when attempting to call IPV user-identity endpoint", e);
            throw new RuntimeException(e);
        }
    }

    public static Optional<ErrorObject> validateUserIdentityResponse(
            UserInfo userIdentityUserInfo, List<VectorOfTrust> vtrList, String trustmarkUrl)
            throws IdentityCallbackException {
        LOG.info("Validating userinfo response");
        for (VectorOfTrust vtr : vtrList) {
            if (vtr.getLevelOfConfidence()
                    .getValue()
                    .equals(userIdentityUserInfo.getClaim(VOT.getValue()))) {

                if (!trustmarkUrl.equals(userIdentityUserInfo.getClaim(VTM.getValue()))) {
                    LOG.warn("VTM does not contain expected trustmark URL");
                    throw new IdentityCallbackException("IPV trustmark is invalid");
                }
                return Optional.empty();
            }
        }
        LOG.warn("IPV missing vot or vot not in vtr list.");
        return Optional.of(OAuth2Error.ACCESS_DENIED);
    }

    public static boolean returnCodePresentInResponse(Object returnCode) {
        return returnCode instanceof List<?> returnCodeList && !returnCodeList.isEmpty();
    }

    public static boolean rpRequestedReturnCode(
            ClientRegistry clientRegistry, AuthenticationRequest authRequest) {
        if (authRequest.getOIDCClaims() == null
                || authRequest.getOIDCClaims().getUserInfoClaimsRequest() == null) {
            return false;
        }
        return clientRegistry.getClaims().contains(RETURN_CODE.getValue())
                && authRequest
                                .getOIDCClaims()
                                .getUserInfoClaimsRequest()
                                .get(RETURN_CODE.getValue())
                        != null;
    }
}
