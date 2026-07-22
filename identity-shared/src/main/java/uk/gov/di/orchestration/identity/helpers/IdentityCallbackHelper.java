package uk.gov.di.orchestration.identity.helpers;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.orchestration.audit.TxmaAuditUser;
import uk.gov.di.orchestration.identity.entity.AuditEventConfiguration;
import uk.gov.di.orchestration.identity.entity.IdentityTokenService;
import uk.gov.di.orchestration.shared.api.CommonFrontend;
import uk.gov.di.orchestration.shared.entity.IdentityClaims;
import uk.gov.di.orchestration.shared.entity.ValidClaims;
import uk.gov.di.orchestration.shared.services.AuditService;
import uk.gov.di.orchestration.shared.services.DynamoIdentityService;
import uk.gov.di.orchestration.shared.services.RedirectService;

import java.util.HashMap;
import java.util.Objects;
import java.util.Optional;

import static uk.gov.di.orchestration.shared.entity.IdentityClaims.VOT;
import static uk.gov.di.orchestration.shared.helpers.InstrumentationHelper.segmentedFunctionCall;

public class IdentityCallbackHelper {

    private static final Logger LOG = LogManager.getLogger(IdentityCallbackHelper.class);
    private final IdentityTokenService identityTokenService;
    private final AuditService auditService;
    private final AuditEventConfiguration auditEventConfiguration;
    private final CommonFrontend frontend;
    private final DynamoIdentityService dynamoIdentityService;

    public IdentityCallbackHelper(
            IdentityTokenService identityTokenService,
            AuditService auditService,
            AuditEventConfiguration auditEventConfiguration,
            CommonFrontend frontend,
            DynamoIdentityService dynamoIdentityService) {
        this.identityTokenService = identityTokenService;
        this.auditService = auditService;
        this.auditEventConfiguration = auditEventConfiguration;
        this.frontend = frontend;
        this.dynamoIdentityService = dynamoIdentityService;
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
}
