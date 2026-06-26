package uk.gov.di.authentication.ipv.services;

import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.OIDCClaimsRequest;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSetRequest;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.ipv.entity.IpvCallbackValidationError;
import uk.gov.di.orchestration.shared.entity.JwksCacheItem;
import uk.gov.di.orchestration.shared.entity.StateItem;
import uk.gov.di.orchestration.shared.helpers.IdGenerator;
import uk.gov.di.orchestration.shared.helpers.NowHelper.NowClock;
import uk.gov.di.orchestration.shared.helpers.RsaKeyHelper;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.JwksCacheService;
import uk.gov.di.orchestration.shared.services.OrchJwtService;
import uk.gov.di.orchestration.shared.services.StateStorageService;

import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.Optional;

public class IPVAuthorisationService {

    private static final Logger LOG = LogManager.getLogger(IPVAuthorisationService.class);
    private final ConfigurationService configurationService;
    private final JwksCacheService jwksCacheService;
    private final StateStorageService stateStorageService;
    private final OrchJwtService orchJwtService;
    private final NowClock nowClock;
    public static final String STATE_STORAGE_PREFIX = "state:";
    public static final String SESSION_INVALIDATED_ERROR_CODE = "session_invalidated";

    public IPVAuthorisationService(ConfigurationService configurationService) {
        this(
                configurationService,
                new JwksCacheService(configurationService),
                new StateStorageService(configurationService),
                new OrchJwtService(configurationService),
                new NowClock(Clock.systemUTC()));
    }

    public IPVAuthorisationService(
            ConfigurationService configurationService,
            JwksCacheService jwksCacheService,
            StateStorageService stateStorageService,
            OrchJwtService orchJwtService,
            NowClock nowClock) {
        this.configurationService = configurationService;
        this.jwksCacheService = jwksCacheService;
        this.stateStorageService = stateStorageService;
        this.orchJwtService = orchJwtService;
        this.nowClock = nowClock;
    }

    public Optional<IpvCallbackValidationError> validateResponse(
            Map<String, String> queryParams, String sessionId) {
        if (queryParams == null || queryParams.isEmpty()) {
            LOG.warn("No Query parameters in IPV Authorisation response");
            return Optional.of(
                    new IpvCallbackValidationError(
                            OAuth2Error.INVALID_REQUEST_CODE, "No query parameters present"));
        }
        if (queryParams.containsKey("error")) {

            if (SESSION_INVALIDATED_ERROR_CODE.equals(queryParams.get("error"))) {
                LOG.warn("Session invalidated response from IPV");
                return Optional.of(
                        new IpvCallbackValidationError(queryParams.get("error"), null, true));
            }

            LOG.warn("Error response found in IPV Authorisation response");
            return Optional.of(new IpvCallbackValidationError(queryParams.get("error"), null));
        }
        if (!queryParams.containsKey("state") || queryParams.get("state").isEmpty()) {
            LOG.warn("No state param in IPV Authorisation response");
            return Optional.of(
                    new IpvCallbackValidationError(
                            OAuth2Error.INVALID_REQUEST_CODE,
                            "No state param present in Authorisation response"));
        }
        if (!isStateValid(sessionId, queryParams.get("state"))) {
            return Optional.of(
                    new IpvCallbackValidationError(
                            OAuth2Error.INVALID_REQUEST_CODE,
                            "Invalid state param present in Authorisation response"));
        }
        if (!queryParams.containsKey("code") || queryParams.get("code").isEmpty()) {
            LOG.warn("No code param in IPV Authorisation response");
            return Optional.of(
                    new IpvCallbackValidationError(
                            OAuth2Error.INVALID_REQUEST_CODE,
                            "No code param present in Authorisation response"));
        }

        return Optional.empty();
    }

    public void storeState(String sessionId, State state) {
        stateStorageService.storeState(STATE_STORAGE_PREFIX + sessionId, state.getValue());
    }

    private boolean isStateValid(String sessionId, String responseState) {
        var valueFromDynamo =
                stateStorageService
                        .getState(STATE_STORAGE_PREFIX + sessionId)
                        .map(StateItem::getState);
        if (valueFromDynamo.isEmpty()) {
            LOG.info("No state found in Dynamo");
            return false;
        }

        State storedState = new State(valueFromDynamo.get());
        LOG.info(
                "Response state: {} and Stored state: {}. Are equal: {}",
                responseState,
                storedState.getValue(),
                responseState.equals(storedState.getValue()));
        return responseState.equals(storedState.getValue());
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
                        .issuer(configurationService.getIPVAuthorisationClientId())
                        .audience(configurationService.getIPVAudience())
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
                                configurationService.getIPVAuthorisationCallbackURI().toString())
                        .claim("client_id", configurationService.getIPVAuthorisationClientId())
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
                RsaKeyHelper.getRsaPublicKeyFromJwksCacheItem(getJwksCacheItemFromJwksEndpoint());
        return orchJwtService.signAndEncryptJWT(
                claimsBuilder.build(),
                configurationService.getIPVTokenSigningKeyAlias(),
                publicEncryptionKey);
    }

    private JwksCacheItem getJwksCacheItemFromJwksEndpoint() {
        LOG.info("Getting IPV Encryption JWK via JWKS endpoint");
        return jwksCacheService.getOrGenerateIpvJwksCacheItem();
    }
}
