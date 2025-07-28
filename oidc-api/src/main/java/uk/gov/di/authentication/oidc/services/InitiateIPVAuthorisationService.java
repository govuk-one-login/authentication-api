package uk.gov.di.authentication.oidc.services;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.OIDCClaimsRequest;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSetRequest;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.ipv.domain.IPVAuditableEvent;
import uk.gov.di.authentication.ipv.services.IPVAuthorisationService;
import uk.gov.di.orchestration.audit.TxmaAuditUser;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.entity.ResponseHeaders;
import uk.gov.di.orchestration.shared.helpers.IpAddressHelper;
import uk.gov.di.orchestration.shared.services.AuditService;
import uk.gov.di.orchestration.shared.services.CloudwatchMetricsService;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.CrossBrowserOrchestrationService;
import uk.gov.di.orchestration.shared.services.TokenService;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static uk.gov.di.orchestration.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.CLIENT_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.attachLogFieldToLogs;
import static uk.gov.di.orchestration.shared.services.AuditService.MetadataPair.pair;

public class InitiateIPVAuthorisationService {

    private static final Logger LOG = LogManager.getLogger(InitiateIPVAuthorisationService.class);

    private final ConfigurationService configurationService;
    private final AuditService auditService;
    private final IPVAuthorisationService authorisationService;
    private final CloudwatchMetricsService cloudwatchMetricsService;
    private final CrossBrowserOrchestrationService crossBrowserOrchestrationService;
    private final TokenService tokenService;

    public InitiateIPVAuthorisationService(
            ConfigurationService configurationService,
            AuditService auditService,
            IPVAuthorisationService authorisationService,
            CloudwatchMetricsService cloudwatchMetricsService,
            CrossBrowserOrchestrationService crossBrowserOrchestrationService,
            TokenService tokenService) {
        this.configurationService = configurationService;
        this.auditService = auditService;
        this.authorisationService = authorisationService;
        this.cloudwatchMetricsService = cloudwatchMetricsService;
        this.crossBrowserOrchestrationService = crossBrowserOrchestrationService;
        this.tokenService = tokenService;
    }

    public APIGatewayProxyResponseEvent sendRequestToIPV(
            APIGatewayProxyRequestEvent input,
            AuthenticationRequest authRequest,
            UserInfo userInfo,
            String sessionId,
            ClientRegistry client,
            String rpClientID,
            String clientSessionId,
            String persistentSessionCookieId,
            Boolean reproveIdentity,
            List<String> levelsOfConfidence) {
        if (!configurationService.isIdentityEnabled()) {
            LOG.error("Identity is not enabled");
            throw new RuntimeException("Identity is not enabled");
        }

        attachLogFieldToLogs(CLIENT_ID, rpClientID);
        LOG.info("AuthenticationCallbackHandler initiated IPV authorisation request");
        var internalCommonSubjectId = userInfo.getSubject();

        var state = new State();
        var claimsSetRequest = buildIpvClaimsRequest(authRequest, internalCommonSubjectId);

        var encryptedJWT =
                authorisationService.constructRequestJWT(
                        state,
                        authRequest.getScope(),
                        internalCommonSubjectId,
                        claimsSetRequest,
                        Optional.ofNullable(clientSessionId).orElse("unknown"),
                        userInfo.getEmailAddress(),
                        levelsOfConfidence,
                        reproveIdentity);

        var authRequestBuilder =
                new AuthorizationRequest.Builder(
                                new ResponseType(ResponseType.Value.CODE),
                                new ClientID(configurationService.getIPVAuthorisationClientId()))
                        .endpointURI(configurationService.getIPVAuthorisationURI())
                        .requestObject(encryptedJWT);

        var ipvAuthorisationRequest = authRequestBuilder.build();
        authorisationService.storeState(sessionId, state);
        crossBrowserOrchestrationService.storeClientSessionIdAgainstState(clientSessionId, state);

        var rpPairwiseId = userInfo.getClaim("rp_pairwise_id");

        auditService.submitAuditEvent(
                IPVAuditableEvent.IPV_AUTHORISATION_REQUESTED,
                rpClientID,
                TxmaAuditUser.user()
                        .withGovukSigninJourneyId(clientSessionId)
                        .withSessionId(sessionId)
                        .withUserId(internalCommonSubjectId.getValue())
                        .withEmail(userInfo.getEmailAddress())
                        .withIpAddress(IpAddressHelper.extractIpAddress(input))
                        .withPersistentSessionId(persistentSessionCookieId),
                pair("clientLandingPageUrl", client.getLandingPageUrl()),
                pair("rpPairwiseId", rpPairwiseId));

        LOG.info(
                "AuthenticationCallbackHandler successfully processed IPV authorisation request, redirect URI {}",
                ipvAuthorisationRequest.toURI().toString());
        cloudwatchMetricsService.incrementCounter(
                "IPVHandoff", Map.of("Environment", configurationService.getEnvironment()));
        return generateApiGatewayProxyResponse(
                302,
                "",
                Map.of(ResponseHeaders.LOCATION, ipvAuthorisationRequest.toURI().toString()),
                null);
    }

    private ClaimsSetRequest buildIpvClaimsRequest(
            AuthenticationRequest authRequest, Subject internalPairwiseSubject) {

        ClaimsSetRequest claimsSetRequest =
                Optional.ofNullable(authRequest)
                        .map(AuthenticationRequest::getOIDCClaims)
                        .map(OIDCClaimsRequest::getUserInfoClaimsRequest)
                        .orElse(new ClaimsSetRequest());

        if (configurationService.sendStorageTokenToIpvEnabled()) {
            LOG.info("Adding storageAccessToken claim to IPV claims request");
            AccessToken storageToken = tokenService.generateStorageToken(internalPairwiseSubject);

            return claimsSetRequest.add(
                    new ClaimsSetRequest.Entry(configurationService.getStorageTokenClaimName())
                            .withValues(List.of(storageToken.getValue())));
        }

        return claimsSetRequest;
    }
}
