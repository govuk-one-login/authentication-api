package uk.gov.di.orchestration.identity.service;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.orchestration.audit.AuditContext;
import uk.gov.di.orchestration.identity.entity.IdentityProgressStatus;
import uk.gov.di.orchestration.identity.entity.LogIds;
import uk.gov.di.orchestration.identity.entity.SPOTClaims;
import uk.gov.di.orchestration.identity.entity.SPOTRequest;
import uk.gov.di.orchestration.shared.api.AuthFrontend;
import uk.gov.di.orchestration.shared.api.OidcAPI;
import uk.gov.di.orchestration.shared.domain.AuditableEvent;
import uk.gov.di.orchestration.shared.entity.AuthUserInfoClaims;
import uk.gov.di.orchestration.shared.entity.IdentityClaims;
import uk.gov.di.orchestration.shared.entity.ResponseHeaders;
import uk.gov.di.orchestration.shared.services.AwsSqsClient;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.RedirectService;
import uk.gov.di.orchestration.shared.services.SerializationService;

import java.util.Map;
import java.util.Optional;

import static uk.gov.di.orchestration.shared.entity.IdentityClaims.VOT;
import static uk.gov.di.orchestration.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;

public class IdentitySPOTService {
    private static final Logger LOG = LogManager.getLogger(IdentitySPOTService.class);
    private final ConfigurationService configurationService;
    private final AwsSqsClient spotSqsClient;
    private final OidcAPI oidcApi;
    private final SerializationService objectMapper;
    private final IdentityProgressService identityProgressService;
    private final AuthFrontend frontend;

    public IdentitySPOTService(
            ConfigurationService configurationService,
            AwsSqsClient spotSqsClient,
            OidcAPI oidcApi,
            SerializationService objectMapper,
            IdentityProgressService identityProgressService,
            AuthFrontend frontend) {
        this.configurationService = configurationService;
        this.spotSqsClient = spotSqsClient;
        this.oidcApi = oidcApi;
        this.objectMapper = objectMapper;
        this.identityProgressService = identityProgressService;
        this.frontend = frontend;
    }

    public void queueSPOTRequest(
            LogIds logIds,
            String sectorIdentifier,
            UserInfo authUserInfo,
            Subject pairwiseSubject,
            UserInfo userIdentityUserInfo,
            String clientId) {
        LOG.info("Constructing SPOT request ready to queue");
        var spotClaimsBuilder =
                SPOTClaims.builder()
                        .withClaim(VOT.getValue(), userIdentityUserInfo.getClaim(VOT.getValue()))
                        .withClaim(
                                IdentityClaims.CREDENTIAL_JWT.getValue(),
                                userIdentityUserInfo
                                        .toJSONObject()
                                        .get(IdentityClaims.CREDENTIAL_JWT.getValue()))
                        .withClaim(
                                IdentityClaims.CORE_IDENTITY.getValue(),
                                userIdentityUserInfo
                                        .toJSONObject()
                                        .get(IdentityClaims.CORE_IDENTITY.getValue()))
                        .withVtm(oidcApi.trustmarkURI().toString());

        var spotRequest =
                new SPOTRequest(
                        spotClaimsBuilder.build(),
                        authUserInfo.getStringClaim(AuthUserInfoClaims.LOCAL_ACCOUNT_ID.getValue()),
                        authUserInfo.getStringClaim(AuthUserInfoClaims.SALT.getValue()),
                        sectorIdentifier,
                        pairwiseSubject.getValue(),
                        logIds,
                        clientId);
        var spotRequestString = objectMapper.writeValueAsString(spotRequest);
        if (configurationService.isNewSpotRequestQueueWritingEnabled()) {
            spotSqsClient.send(spotRequestString);
        }
        LOG.info("SPOT request placed on queue");
    }

    // This method returns error redirects but ALSO returns the immediate
    // redirect to the frontend spinner page
    // Hopefully this doesn't exist for much longer so we can remove it soon
    // We return an empty optional for a successful sync wait for spot
    //  so we can check for interventions, generate an auth code, and emit audit events + metrics
    public Optional<APIGatewayProxyResponseEvent> waitForSpot(
            String clientSessionId, AuditContext auditContext, AuditableEvent auditableEvent)
            throws InterruptedException {
        if (configurationService.isSyncWaitForSpotEnabled()) {
            var status =
                    identityProgressService.pollForStatus(
                            clientSessionId, auditContext, auditableEvent);
            if (status == IdentityProgressStatus.NO_ENTRY) {
                return Optional.of(
                        RedirectService.redirectToFrontendErrorPageWithErrorLog(
                                frontend.errorURI(),
                                new Error("Identity processing returned NO_ENTRY")));
            }
            if (status == IdentityProgressStatus.ERROR) {
                return Optional.of(
                        RedirectService.redirectToFrontendErrorPageWithErrorLog(
                                frontend.errorURI(), new Error("Identity processing failed")));
            }
            if (status == IdentityProgressStatus.COMPLETED) {
                return Optional.empty();
            }
        } else {
            LOG.info("Successful IPV callback. Redirecting to frontend");
            return Optional.of(
                    generateApiGatewayProxyResponse(
                            302,
                            "",
                            Map.of(ResponseHeaders.LOCATION, frontend.ipvCallbackURI().toString()),
                            null));
        }
        return Optional.of(
                RedirectService.redirectToFrontendErrorPageWithErrorLog(
                        frontend.errorURI(), new Error("Failed to create redirectURI")));
    }
}
