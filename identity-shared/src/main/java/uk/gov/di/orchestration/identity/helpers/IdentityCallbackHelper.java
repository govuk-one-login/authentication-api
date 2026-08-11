package uk.gov.di.orchestration.identity.helpers;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.orchestration.identity.exceptions.IdentityCallbackException;
import uk.gov.di.orchestration.shared.api.AuthFrontend;
import uk.gov.di.orchestration.shared.api.CommonFrontend;
import uk.gov.di.orchestration.shared.api.OidcAPI;
import uk.gov.di.orchestration.shared.entity.IdentityClaims;
import uk.gov.di.orchestration.shared.entity.LevelOfConfidence;
import uk.gov.di.orchestration.shared.entity.ValidClaims;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.DynamoIdentityService;
import uk.gov.di.orchestration.shared.services.RedirectService;

import java.util.HashMap;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import static uk.gov.di.orchestration.shared.entity.IdentityClaims.VOT;
import static uk.gov.di.orchestration.shared.entity.IdentityClaims.VTM;

public class IdentityCallbackHelper {

    private static final Logger LOG = LogManager.getLogger(IdentityCallbackHelper.class);
    private final CommonFrontend frontend;
    private final DynamoIdentityService dynamoIdentityService;
    private final OidcAPI oidcAPI;

    public IdentityCallbackHelper(ConfigurationService configurationService) {
        this(
                new AuthFrontend(configurationService),
                new DynamoIdentityService(configurationService),
                new OidcAPI(configurationService));
    }

    public IdentityCallbackHelper(
            CommonFrontend frontend, DynamoIdentityService dynamoIdentityService, OidcAPI oidcAPI) {
        this.frontend = frontend;
        this.dynamoIdentityService = dynamoIdentityService;
        this.oidcAPI = oidcAPI;
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

    public Optional<ErrorObject> validateUserIdentityResponse(
            UserInfo userIdentityUserInfo, List<LevelOfConfidence> locList)
            throws IdentityCallbackException {
        LOG.info("Validating userinfo response");
        for (LevelOfConfidence loc : locList) {
            if (loc.getValue().equals(userIdentityUserInfo.getClaim(VOT.getValue()))) {
                var trustmarkURL = oidcAPI.trustmarkURI().toString();

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

    public APIGatewayProxyResponseEvent redirectToFrontendErrorPageWithErrorLog(Throwable error) {
        return RedirectService.redirectToFrontendErrorPageWithErrorLog(frontend.errorURI(), error);
    }

    public APIGatewayProxyResponseEvent redirectToFrontendErrorPageForNoSession(
            Exception exception) {
        return RedirectService.redirectToFrontendErrorPageForNoSession(
                frontend.sessionEndedURI(), exception);
    }

    public APIGatewayProxyResponseEvent redirectToFrontendErrorPageWithWarnLog(
            Exception exception) {
        return RedirectService.redirectToFrontendErrorPageWithWarnLog(
                frontend.errorURI(), exception);
    }
}
