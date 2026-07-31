package uk.gov.di.orchestration.identity.helpers;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import com.nimbusds.openid.connect.sdk.UserInfoResponse;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.orchestration.audit.TxmaAuditUser;
import uk.gov.di.orchestration.identity.entity.AuditEventConfiguration;
import uk.gov.di.orchestration.identity.exceptions.IdentityCallbackException;
import uk.gov.di.orchestration.identity.service.IdentityTokenService;
import uk.gov.di.orchestration.shared.api.CommonFrontend;
import uk.gov.di.orchestration.shared.api.OidcAPI;
import uk.gov.di.orchestration.shared.entity.IdentityClaims;
import uk.gov.di.orchestration.shared.entity.LevelOfConfidence;
import uk.gov.di.orchestration.shared.entity.ValidClaims;
import uk.gov.di.orchestration.shared.exceptions.UnsuccessfulCredentialResponseException;
import uk.gov.di.orchestration.shared.helpers.ConstructUriHelper;
import uk.gov.di.orchestration.shared.services.AuditService;
import uk.gov.di.orchestration.shared.services.DynamoIdentityService;
import uk.gov.di.orchestration.shared.services.RedirectService;

import java.io.IOException;
import java.net.URI;
import java.util.HashMap;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import static java.lang.String.format;
import static uk.gov.di.orchestration.shared.entity.IdentityClaims.VOT;
import static uk.gov.di.orchestration.shared.entity.IdentityClaims.VTM;
import static uk.gov.di.orchestration.shared.helpers.InstrumentationHelper.segmentedFunctionCall;

public class IdentityCallbackHelper {

    private static final Logger LOG = LogManager.getLogger(IdentityCallbackHelper.class);
    private final IdentityTokenService identityTokenService;
    private final AuditService auditService;
    private final AuditEventConfiguration auditEventConfiguration;
    private final CommonFrontend frontend;
    private final DynamoIdentityService dynamoIdentityService;
    private final OidcAPI oidcAPI;

    public IdentityCallbackHelper(
            IdentityTokenService identityTokenService,
            AuditService auditService,
            AuditEventConfiguration auditEventConfiguration,
            CommonFrontend frontend,
            DynamoIdentityService dynamoIdentityService,
            OidcAPI oidcAPI) {
        this.identityTokenService = identityTokenService;
        this.auditService = auditService;
        this.auditEventConfiguration = auditEventConfiguration;
        this.frontend = frontend;
        this.dynamoIdentityService = dynamoIdentityService;
        this.oidcAPI = oidcAPI;
    }

    public Optional<APIGatewayProxyResponseEvent> makeTokenRequest(
            String authCode, String clientId, TxmaAuditUser user) {
        var tokenResponse =
                segmentedFunctionCall("getToken", () -> identityTokenService.getToken(authCode));
        if (!tokenResponse.indicatesSuccess()) {
            auditService.submitAuditEvent(
                    auditEventConfiguration.unsuccessfulTokenResponseReceived(), clientId, user);
            return Optional.of(
                    RedirectService.redirectToFrontendErrorPageWithErrorLog(
                            frontend.errorURI(),
                            new Exception(
                                    String.format(
                                            "TokenResponse was not successful: %s",
                                            tokenResponse.toErrorResponse().toJSONObject()))));
        }
        auditService.submitAuditEvent(
                auditEventConfiguration.successfulTokenResponseReceived(), clientId, user);
        return Optional.empty();
    }

    public void saveIdentityClaimsToDynamo(
            String clientSessionId,
            Subject rpPairwiseSubject,
            UserInfo userIdentityUserInfo,
            Long spotQueuedAt) {
        LOG.info("Checking for additional identity claims to save to dynamo");
        var additionalClaims = new HashMap<String, String>();
        ValidClaims.getAllValidClaims().stream()
                .filter(t -> !t.equals(ValidClaims.CORE_IDENTITY_JWT.getValue()))
                .filter(claim -> Objects.nonNull(userIdentityUserInfo.toJSONObject().get(claim)))
                .forEach(
                        finalClaim ->
                                additionalClaims.put(
                                        finalClaim,
                                        userIdentityUserInfo
                                                .toJSONObject()
                                                .get(finalClaim)
                                                .toString()));
        LOG.info("Additional identity claims present: {}", !additionalClaims.isEmpty());

        var ipvCoreIdentityClaim =
                userIdentityUserInfo.getClaim(IdentityClaims.CORE_IDENTITY.getValue());
        String ipvCoreIdentityString =
                ipvCoreIdentityClaim == null ? "" : ipvCoreIdentityClaim.toString();
        dynamoIdentityService.saveIdentityClaims(
                clientSessionId,
                rpPairwiseSubject.getValue(),
                additionalClaims,
                (String) userIdentityUserInfo.getClaim(VOT.getValue()),
                ipvCoreIdentityString,
                spotQueuedAt);
    }

    public UserInfo sendUserIdentityRequest(TokenResponse tokenResponse, URI backendUri)
            throws UnsuccessfulCredentialResponseException {
        return sendUserIdentityRequest(createUserIdentityRequest(tokenResponse, backendUri));
    }

    HTTPRequest createUserIdentityRequest(TokenResponse tokenResponse, URI backendUri) {
        return new UserInfoRequest(
                        ConstructUriHelper.buildURI(backendUri, "user-identity"),
                        tokenResponse.toSuccessResponse().getTokens().getBearerAccessToken())
                .toHTTPRequest();
    }

    UserInfo sendUserIdentityRequest(HTTPRequest httpRequest)
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
                            format(
                                    "Unsuccessful %s response from user identity endpoint on attempt %d: %s ",
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
            LOG.error("Error when attempting to call user-identity endpoint", e);
            throw new RuntimeException(e);
        }
    }

    public Optional<ErrorObject> validateUserIdentityResponse(
            UserInfo userIdentityUserInfo, List<LevelOfConfidence> locList)
            throws IdentityCallbackException {
        LOG.info("Validating userinfo response");
        for (LevelOfConfidence loc : locList) {
            if (loc.getValue().equals(userIdentityUserInfo.getClaim(VOT.getValue()))) {

                if (!oidcAPI.trustmarkURI().equals(userIdentityUserInfo.getClaim(VTM.getValue()))) {
                    LOG.warn("VTM does not contain expected trustmark URL");
                    throw new IdentityCallbackException("Identity trustmark is invalid");
                }
                return Optional.empty();
            }
        }
        LOG.warn("User identity response missing vot or vot not in vtr list.");
        return Optional.of(OAuth2Error.ACCESS_DENIED);
    }

    public APIGatewayProxyResponseEvent redirectToFrontendErrorPageWithErrorLog(Throwable error) {
        return RedirectService.redirectToFrontendErrorPageWithErrorLog(frontend.errorURI(), error);
    }

    public APIGatewayProxyResponseEvent redirectToFrontendErrorPageForNoSession(
            Exception exception) {
        return RedirectService.redirectToFrontendErrorPageForNoSession(
                frontend.sessionEndedURI(), exception);
    }
}
