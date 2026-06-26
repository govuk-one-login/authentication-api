package uk.gov.di.orchestration.shared.services;

import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.State;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.entity.JwksCacheItem;
import uk.gov.di.orchestration.shared.entity.StateItem;
import uk.gov.di.orchestration.shared.helpers.IdGenerator;
import uk.gov.di.orchestration.shared.helpers.NowHelper;
import uk.gov.di.orchestration.shared.helpers.RsaKeyHelper;

import java.time.Clock;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.Optional;

public class DocAppAuthorisationService {

    private static final Logger LOG = LogManager.getLogger(DocAppAuthorisationService.class);
    private final ConfigurationService configurationService;
    private final JwksCacheService jwksCacheService;
    private final StateStorageService stateStorageService;
    private final OrchJwtService orchJwtService;
    private final NowHelper.NowClock nowClock;
    public static final String STATE_STORAGE_PREFIX = "state:";

    public static final String STATE_PARAM = "state";

    public DocAppAuthorisationService(
            ConfigurationService configurationService,
            JwksCacheService jwksCacheService,
            StateStorageService stateStorageService,
            OrchJwtService orchJwtService,
            Clock clock) {
        this.configurationService = configurationService;
        this.jwksCacheService = jwksCacheService;
        this.stateStorageService = stateStorageService;
        this.orchJwtService = orchJwtService;
        this.nowClock = new NowHelper.NowClock(clock);
    }

    public DocAppAuthorisationService(
            ConfigurationService configurationService,
            JwksCacheService jwksCacheService,
            StateStorageService stateStorageService,
            OrchJwtService orchJwtService) {
        this.configurationService = configurationService;
        this.jwksCacheService = jwksCacheService;
        this.stateStorageService = stateStorageService;
        this.orchJwtService = orchJwtService;
        this.nowClock = new NowHelper.NowClock(Clock.systemUTC());
    }

    public Optional<ErrorObject> validateResponse(Map<String, String> headers, String sessionId) {
        LOG.info("Validating AuthorisationResponse");
        if (headers == null || headers.isEmpty()) {
            LOG.warn("No Query parameters in Doc Checking App Authorisation response");
            return Optional.of(
                    new ErrorObject(
                            OAuth2Error.INVALID_REQUEST_CODE, "No query parameters present"));
        }
        if (headers.containsKey("error")) {
            LOG.warn("Error response found in Doc Checking App Authorisation response");
            return Optional.of(new ErrorObject(headers.get("error")));
        }
        if (!headers.containsKey(STATE_PARAM) || headers.get(STATE_PARAM).isEmpty()) {
            LOG.warn("No state param in Doc Checking App Authorisation response");
            return Optional.of(
                    new ErrorObject(
                            OAuth2Error.INVALID_REQUEST_CODE,
                            "No state param present in Authorisation response"));
        }
        if (!isStateValid(sessionId, headers.get(STATE_PARAM))) {
            return Optional.of(
                    new ErrorObject(
                            OAuth2Error.INVALID_REQUEST_CODE,
                            "Invalid state param present in Authorisation response"));
        }
        if (!headers.containsKey("code") || headers.get("code").isEmpty()) {
            LOG.warn("No code param in Doc Checking App Authorisation response");
            return Optional.of(
                    new ErrorObject(
                            OAuth2Error.INVALID_REQUEST_CODE,
                            "No code param present in Authorisation response"));
        }
        LOG.info("AuthorisationResponse passed validation");
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
            LOG.info("No Doc Checking App state found in Dynamo");
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
            String subjectValue,
            ClientRegistry clientRegistry,
            String clientSessionId) {
        LOG.info("Generating request JWT");
        var jwtID = IdGenerator.generate();
        var expiryDate =
                clientRegistry.isTestClient()
                        ? nowClock.nowPlus(5, ChronoUnit.DAYS)
                        : nowClock.nowPlus(3, ChronoUnit.MINUTES);
        var audience =
                configurationService.isDocAppNewAudClaimEnabled()
                        ? configurationService.getDocAppAudClaim()
                        : new Audience(configurationService.getDocAppAuthorisationURI());
        var claimsBuilder =
                new JWTClaimsSet.Builder()
                        .issuer(configurationService.getDocAppAuthorisationClientId())
                        .audience(audience.getValue())
                        .expirationTime(expiryDate)
                        .subject(subjectValue)
                        .issueTime(nowClock.now())
                        .notBeforeTime(nowClock.now())
                        .jwtID(jwtID)
                        .claim(STATE_PARAM, state.getValue())
                        .claim(
                                "redirect_uri",
                                configurationService.getDocAppAuthorisationCallbackURI().toString())
                        .claim("client_id", configurationService.getDocAppAuthorisationClientId())
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("govuk_signin_journey_id", clientSessionId);
        if (clientRegistry.isTestClient()) {
            claimsBuilder.claim("test_client", true);
        }
        var publicEncryptionKey =
                RsaKeyHelper.getRsaPublicKeyFromJwksCacheItem(getPublicEncryptionKey());
        return orchJwtService.signAndEncryptJWT(
                claimsBuilder.build(),
                configurationService.getDocAppTokenSigningKeyAlias(),
                publicEncryptionKey);
    }

    private JwksCacheItem getPublicEncryptionKey() {
        LOG.info("Getting Doc App Auth Encryption Public Key via JWKS endpoint");
        return jwksCacheService.getOrGenerateDocAppJwksCacheItem();
    }
}
