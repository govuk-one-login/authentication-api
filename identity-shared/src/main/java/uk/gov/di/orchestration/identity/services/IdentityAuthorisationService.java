package uk.gov.di.orchestration.identity.services;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
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
import uk.gov.di.orchestration.audit.TxmaAuditUser;
import uk.gov.di.orchestration.identity.entity.IdentityAuthConfiguration;
import uk.gov.di.orchestration.shared.entity.ResponseHeaders;
import uk.gov.di.orchestration.shared.helpers.IdGenerator;
import uk.gov.di.orchestration.shared.helpers.NowHelper;
import uk.gov.di.orchestration.shared.helpers.RsaKeyHelper;
import uk.gov.di.orchestration.shared.services.AuditService;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.CrossBrowserOrchestrationService;
import uk.gov.di.orchestration.shared.services.Metrics;
import uk.gov.di.orchestration.shared.services.OrchJwtService;
import uk.gov.di.orchestration.shared.services.StateStorageService;
import uk.gov.di.orchestration.shared.services.TokenService;

import java.security.interfaces.RSAPublicKey;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static uk.gov.di.orchestration.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.CLIENT_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.attachLogFieldToLogs;
import static uk.gov.di.orchestration.shared.services.AuditService.MetadataPair.pair;

public class IdentityAuthorisationService {
    private static final Logger LOG = LogManager.getLogger(IdentityAuthorisationService.class);
    private final ConfigurationService configurationService;
    private final TokenService tokenService;
    private final StateStorageService stateStorageService;
    private final CrossBrowserOrchestrationService crossBrowserOrchestrationService;
    private final OrchJwtService orchJwtService;
    private final NowHelper.NowClock nowClock;
    private final AuditService auditService;
    private final Metrics metrics;
    private final IdentityAuthConfiguration identityAuthConfiguration;

    public IdentityAuthorisationService(
            ConfigurationService configurationService,
            TokenService tokenService,
            StateStorageService stateStorageService,
            CrossBrowserOrchestrationService crossBrowserOrchestrationService,
            OrchJwtService orchJwtService,
            NowHelper.NowClock nowClock,
            AuditService auditService,
            Metrics metrics,
            IdentityAuthConfiguration identityAuthConfiguration) {
        this.configurationService = configurationService;
        this.tokenService = tokenService;
        this.stateStorageService = stateStorageService;
        this.crossBrowserOrchestrationService = crossBrowserOrchestrationService;
        this.orchJwtService = orchJwtService;
        this.nowClock = nowClock;
        this.auditService = auditService;
        this.metrics = metrics;
        this.identityAuthConfiguration = identityAuthConfiguration;
    }

    public APIGatewayProxyResponseEvent sendRequest(
            AuthenticationRequest authRequest,
            UserInfo userInfo,
            String rpClientID,
            String sessionId,
            String clientSessionId,
            Boolean reproveIdentity,
            List<String> levelsOfConfidence,
            String ipAddress,
            String persistentSessionId,
            String landingPageUrl) {
        if (!configurationService.isIdentityEnabled()) {
            LOG.error("Identity is not enabled");
            throw new RuntimeException("Identity is not enabled");
        }

        attachLogFieldToLogs(CLIENT_ID, rpClientID);
        LOG.info("Initiated identity authorisation request");
        var internalCommonSubjectId = userInfo.getSubject();

        var state = new State();

        var claimsSetRequest = buildClaimsRequest(authRequest, internalCommonSubjectId);

        var encryptedJWT =
                constructRequestJWT(
                        state,
                        authRequest.getScope(),
                        internalCommonSubjectId,
                        claimsSetRequest,
                        Optional.ofNullable(clientSessionId).orElse("unknown"),
                        userInfo.getEmailAddress(),
                        levelsOfConfidence,
                        reproveIdentity);

        var identityAuthRequest =
                new AuthorizationRequest.Builder(
                                new ResponseType(ResponseType.Value.CODE),
                                new ClientID(identityAuthConfiguration.clientId()))
                        .endpointURI(identityAuthConfiguration.authorisationUri())
                        .requestObject(encryptedJWT)
                        .build();
        stateStorageService.storeState(
                identityAuthConfiguration.stateStoragePrefix() + sessionId, state.getValue());
        crossBrowserOrchestrationService.storeClientSessionIdAgainstState(clientSessionId, state);

        var rpPairwiseId = userInfo.getClaim("rp_pairwise_id");

        auditService.submitAuditEvent(
                identityAuthConfiguration.auditEvent(),
                rpClientID,
                TxmaAuditUser.user()
                        .withGovukSigninJourneyId(clientSessionId)
                        .withSessionId(sessionId)
                        .withUserId(internalCommonSubjectId.getValue())
                        .withEmail(userInfo.getEmailAddress())
                        .withIpAddress(ipAddress)
                        .withPersistentSessionId(persistentSessionId),
                pair("clientLandingPageUrl", landingPageUrl),
                pair("rpPairwiseId", rpPairwiseId));

        LOG.info(
                "Successfully processed identity authorisation request, redirect URI {}",
                identityAuthRequest.toURI().toString());
        metrics.increment(
                identityAuthConfiguration.metricToIncrement(),
                Map.of("Environment", configurationService.getEnvironment()));
        LOG.info(
                "Successfully processed identity authorisation request, redirect URI {}",
                identityAuthRequest.toURI().toString());
        return generateApiGatewayProxyResponse(
                302,
                "",
                Map.of(ResponseHeaders.LOCATION, identityAuthRequest.toURI().toString()),
                null);
    }

    private ClaimsSetRequest buildClaimsRequest(
            AuthenticationRequest authRequest, Subject internalPairwiseSubject) {

        ClaimsSetRequest claimsSetRequest =
                Optional.ofNullable(authRequest)
                        .map(AuthenticationRequest::getOIDCClaims)
                        .map(OIDCClaimsRequest::getUserInfoClaimsRequest)
                        .orElse(new ClaimsSetRequest());

        LOG.info("Adding storageAccessToken claim to SIS claims request");
        AccessToken storageToken =
                tokenService.generateStorageToken(
                        internalPairwiseSubject, identityAuthConfiguration.audience());

        return claimsSetRequest.add(
                new ClaimsSetRequest.Entry(configurationService.getStorageTokenClaimName())
                        .withValues(List.of(storageToken.getValue())));
    }

    public EncryptedJWT constructRequestJWT(
            State state,
            Scope scope,
            Subject subject,
            ClaimsSetRequest claims,
            String clientSessionId,
            String emailAddress,
            List<String> vtr,
            Boolean reproveIdentity) {
        LOG.info("Generating request JWT");
        var jwtID = IdGenerator.generate();
        var expiryDate = nowClock.nowPlus(3, ChronoUnit.MINUTES);
        var claimsRequest = new OIDCClaimsRequest().withUserInfoClaimsRequest(claims);
        var claimsBuilder =
                new JWTClaimsSet.Builder()
                        .issuer(identityAuthConfiguration.clientId())
                        .audience(identityAuthConfiguration.audience())
                        .expirationTime(expiryDate)
                        .subject(subject.getValue())
                        .issueTime(nowClock.now())
                        .jwtID(jwtID)
                        .notBeforeTime(nowClock.now())
                        .claim("state", state.getValue())
                        .claim("govuk_signin_journey_id", clientSessionId)
                        .claim("email_address", emailAddress)
                        .claim("redirect_uri", identityAuthConfiguration.callbackUri())
                        .claim("client_id", identityAuthConfiguration.clientId())
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", scope.toString())
                        .claim("vtr", vtr);
        if (configurationService.isAccountInterventionServiceActionEnabled()
                && reproveIdentity != null) {
            claimsBuilder.claim("reprove_identity", reproveIdentity);
        }
        claimsBuilder.claim("claims", claimsRequest.toJSONObject());
        LOG.info("Encrypted request JWT has been generated");
        RSAPublicKey publicEncryptionKey =
                RsaKeyHelper.getRsaPublicKeyFromJwksCacheItem(
                        identityAuthConfiguration.jwksCacheItemSupplier().get());
        return orchJwtService.signAndEncryptJWT(
                claimsBuilder.build(),
                identityAuthConfiguration.tokenSigningKeyAlias(),
                publicEncryptionKey);
    }
}
