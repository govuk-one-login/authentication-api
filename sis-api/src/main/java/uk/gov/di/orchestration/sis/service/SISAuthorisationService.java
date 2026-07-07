package uk.gov.di.orchestration.sis.service;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.OAuth2Error;
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
import uk.gov.di.orchestration.shared.entity.ResponseHeaders;
import uk.gov.di.orchestration.shared.helpers.IdGenerator;
import uk.gov.di.orchestration.shared.helpers.NowHelper;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.CrossBrowserOrchestrationService;
import uk.gov.di.orchestration.shared.services.JwksCacheService;
import uk.gov.di.orchestration.shared.services.OrchJwtService;
import uk.gov.di.orchestration.shared.services.StateStorageService;
import uk.gov.di.orchestration.shared.services.TokenService;
import uk.gov.di.orchestration.sis.exception.SISCallbackValidationError;

import java.security.interfaces.RSAPublicKey;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static uk.gov.di.orchestration.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.CLIENT_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.attachLogFieldToLogs;
import static uk.gov.di.orchestration.shared.helpers.RsaKeyHelper.getRsaPublicKeyFromJwksCacheItem;

public class SISAuthorisationService {
    private static final String STATE_STORAGE_PREFIX = "sis-state:";
    private static final Logger LOG = LogManager.getLogger(SISAuthorisationService.class);
    private final ConfigurationService configurationService;
    private final TokenService tokenService;
    private final StateStorageService stateStorageService;
    private final CrossBrowserOrchestrationService crossBrowserOrchestrationService;
    private final JwksCacheService jwksCacheService;
    private final OrchJwtService orchJwtService;
    private final NowHelper.NowClock nowClock;

    public SISAuthorisationService(
            ConfigurationService configurationService,
            TokenService tokenService,
            StateStorageService stateStorageService,
            CrossBrowserOrchestrationService crossBrowserOrchestrationService,
            JwksCacheService jwksCacheService,
            OrchJwtService orchJwtService,
            NowHelper.NowClock nowClock) {
        this.configurationService = configurationService;
        this.tokenService = tokenService;
        this.stateStorageService = stateStorageService;
        this.crossBrowserOrchestrationService = crossBrowserOrchestrationService;
        this.jwksCacheService = jwksCacheService;
        this.orchJwtService = orchJwtService;
        this.nowClock = nowClock;
    }

    public APIGatewayProxyResponseEvent sendRequest(
            AuthenticationRequest authRequest,
            UserInfo userInfo,
            String rpClientID,
            String sessionId,
            String clientSessionId,
            Boolean reproveIdentity,
            List<String> levelsOfConfidence) {
        if (!configurationService.isIdentityEnabled()) {
            LOG.error("Identity is not enabled");
            throw new RuntimeException("Identity is not enabled");
        }

        attachLogFieldToLogs(CLIENT_ID, rpClientID);
        LOG.info("Initiated SIS authorisation request");
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

        var sisAuthRequest =
                new AuthorizationRequest.Builder(
                                new ResponseType(ResponseType.Value.CODE),
                                new ClientID(configurationService.getSISAuthorisationClientId()))
                        .endpointURI(configurationService.getSISAuthorisationURI())
                        .requestObject(encryptedJWT)
                        .build();
        stateStorageService.storeState(STATE_STORAGE_PREFIX + sessionId, state.getValue());
        crossBrowserOrchestrationService.storeClientSessionIdAgainstState(clientSessionId, state);
        // TODO: Add audit events
        // TODO: Add cloudwatch metric for SISHandoff
        LOG.info(
                "Successfully processed SIS authorisation request, redirect URI {}",
                sisAuthRequest.toURI().toString());
        return generateApiGatewayProxyResponse(
                302, "", Map.of(ResponseHeaders.LOCATION, sisAuthRequest.toURI().toString()), null);
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
                        .issuer(configurationService.getSISAuthorisationClientId())
                        .audience(configurationService.getSISAudience())
                        .expirationTime(expiryDate)
                        .subject(subject.getValue())
                        .issueTime(nowClock.now())
                        .jwtID(jwtID)
                        .notBeforeTime(nowClock.now())
                        .claim("state", state.getValue())
                        .claim("govuk_signin_journey_id", clientSessionId)
                        .claim("email_address", emailAddress)
                        .claim(
                                "redirect_uri",
                                configurationService.getSISAuthorisationCallbackURI().toString())
                        .claim("client_id", configurationService.getSISAuthorisationClientId())
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", scope.toString())
                        .claim("vtr", vtr);
        if (configurationService.isAccountInterventionServiceActionEnabled()
                && reproveIdentity != null) {
            claimsBuilder.claim("reprove_identity", reproveIdentity);
        }
        claimsBuilder.claim("claims", claimsRequest.toJSONObject());
        LOG.info("Encrypted request JWT has been generated");
        return orchJwtService.signAndEncryptJWT(
                claimsBuilder.build(),
                configurationService.getSISTokenSigningKeyAlias(),
                getPublicEncryptionKey());
    }

    private RSAPublicKey getPublicEncryptionKey() {
        LOG.info("Getting SIS Encryption JWK via JWKS endpoint");
        return getRsaPublicKeyFromJwksCacheItem(jwksCacheService.getOrGenerateSISJwksCacheItem());
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
                        internalPairwiseSubject, configurationService.getSISAudience());

        return claimsSetRequest.add(
                new ClaimsSetRequest.Entry(configurationService.getStorageTokenClaimName())
                        .withValues(List.of(storageToken.getValue())));
    }

    public Optional<SISCallbackValidationError> validateResponse(
            Map<String, String> queryParams, String sessionId) {
        if (queryParams == null || queryParams.isEmpty()) {
            LOG.warn("No Query parameters in SIS Authorisation response");
            return Optional.of(
                    new SISCallbackValidationError(
                            OAuth2Error.INVALID_REQUEST_CODE, "No query parameters present"));
        }

        return Optional.empty();
    }
}
