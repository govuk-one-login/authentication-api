package uk.gov.di.authentication.oidc.services;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.OIDCClaimsRequest;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSetRequest;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.ipv.domain.IPVAuditableEvent;
import uk.gov.di.authentication.ipv.services.IPVAuthorisationService;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.ResponseHeaders;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.helpers.IpAddressHelper;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.util.Map;
import java.util.Optional;

import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.LogFieldName.CLIENT_ID;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachLogFieldToLogs;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;

public class InitiateIPVAuthorisationService {

    private static final Logger LOG = LogManager.getLogger(InitiateIPVAuthorisationService.class);

    private final ConfigurationService configurationService;
    private final AuditService auditService;
    private final IPVAuthorisationService authorisationService;
    private final CloudwatchMetricsService cloudwatchMetricsService;

    public InitiateIPVAuthorisationService(
            ConfigurationService configurationService,
            AuditService auditService,
            IPVAuthorisationService authorisationService,
            CloudwatchMetricsService cloudwatchMetricsService) {
        this.configurationService = configurationService;
        this.auditService = auditService;
        this.authorisationService = authorisationService;
        this.cloudwatchMetricsService = cloudwatchMetricsService;
    }

    public APIGatewayProxyResponseEvent sendRequestToIPV(
            APIGatewayProxyRequestEvent input,
            AuthenticationRequest authRequest,
            UserInfo userInfo,
            Session session,
            ClientRegistry client,
            String rpClientID,
            String clientSessionId,
            String persistentSessionCookieId) {
        if (!configurationService.isIdentityEnabled()) {
            LOG.error("Identity is not enabled");
            throw new RuntimeException("Identity is not enabled");
        }

        attachLogFieldToLogs(CLIENT_ID, rpClientID);
        LOG.info("IPVAuthorisationHandler received request");
        var pairwiseSubject = userInfo.getSubject();

        var state = new State();
        var claimsSetRequest =
                buildIpvClaimsRequest(authRequest).map(ClaimsSetRequest::toJSONString).orElse(null);

        var encryptedJWT =
                authorisationService.constructRequestJWT(
                        state,
                        authRequest.getScope(),
                        pairwiseSubject,
                        claimsSetRequest,
                        Optional.ofNullable(clientSessionId).orElse("unknown"),
                        userInfo.getEmailAddress(),
                        authRequest.getCustomParameter("vtr"));
        var authRequestBuilder =
                new AuthorizationRequest.Builder(
                                new ResponseType(ResponseType.Value.CODE),
                                new ClientID(configurationService.getIPVAuthorisationClientId()))
                        .endpointURI(configurationService.getIPVAuthorisationURI())
                        .requestObject(encryptedJWT);

        var ipvAuthorisationRequest = authRequestBuilder.build();
        authorisationService.storeState(session.getSessionId(), state);

        var rpPairwiseId = userInfo.getClaim("rp_pairwise_id");

        auditService.submitAuditEvent(
                IPVAuditableEvent.IPV_AUTHORISATION_REQUESTED,
                clientSessionId,
                session.getSessionId(),
                rpClientID,
                session.getInternalCommonSubjectIdentifier(),
                userInfo.getEmailAddress(),
                IpAddressHelper.extractIpAddress(input),
                AuditService.UNKNOWN,
                persistentSessionCookieId,
                pair("clientLandingPageUrl", client.getLandingPageUrl()),
                pair("rpPairwiseId", rpPairwiseId));

        LOG.info(
                "IPVAuthorisationHandler successfully processed request, redirect URI {}",
                ipvAuthorisationRequest.toURI().toString());
        cloudwatchMetricsService.incrementCounter(
                "IPVHandoff", Map.of("Environment", configurationService.getEnvironment()));
        return generateApiGatewayProxyResponse(
                302,
                "",
                Map.of(ResponseHeaders.LOCATION, ipvAuthorisationRequest.toURI().toString()),
                null);
    }

    private Optional<ClaimsSetRequest> buildIpvClaimsRequest(AuthenticationRequest authRequest) {
        return Optional.ofNullable(authRequest)
                .map(AuthenticationRequest::getOIDCClaims)
                .map(OIDCClaimsRequest::getUserInfoClaimsRequest);
    }
}
