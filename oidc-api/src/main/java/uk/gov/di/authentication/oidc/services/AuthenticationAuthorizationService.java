package uk.gov.di.authentication.oidc.services;

import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.OIDCClaimsRequest;
import com.nimbusds.openid.connect.sdk.OIDCError;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.Prompt;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSetRequest;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.oidc.exceptions.AuthenticationAuthorisationRequestException;
import uk.gov.di.authentication.oidc.exceptions.AuthenticationCallbackValidationException;
import uk.gov.di.orchestration.shared.api.AuthFrontend;
import uk.gov.di.orchestration.shared.entity.AuthUserInfoClaims;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.entity.CustomScopeValue;
import uk.gov.di.orchestration.shared.entity.OrchSessionItem;
import uk.gov.di.orchestration.shared.entity.StateItem;
import uk.gov.di.orchestration.shared.entity.VectorOfTrust;
import uk.gov.di.orchestration.shared.helpers.ClientSubjectHelper;
import uk.gov.di.orchestration.shared.helpers.IdGenerator;
import uk.gov.di.orchestration.shared.helpers.NowHelper;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.JwksService;
import uk.gov.di.orchestration.shared.services.KmsConnectionService;
import uk.gov.di.orchestration.shared.services.StateStorageService;
import uk.gov.di.orchestration.shared.services.TokenValidationService;

import java.net.URI;
import java.time.Clock;
import java.time.temporal.ChronoUnit;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import static com.nimbusds.oauth2.sdk.OAuth2Error.ACCESS_DENIED_CODE;
import static com.nimbusds.openid.connect.sdk.SubjectType.PUBLIC;
import static uk.gov.di.authentication.oidc.entity.AuthErrorCodes.SFAD_ERROR;
import static uk.gov.di.authentication.oidc.helpers.AuthRequestHelper.getCustomParameterOpt;
import static uk.gov.di.orchestration.shared.conditions.IdentityHelper.identityRequired;
import static uk.gov.di.orchestration.shared.helpers.InstrumentationHelper.segmentedFunctionCall;

public class AuthenticationAuthorizationService {
    private static final Logger LOG =
            LogManager.getLogger(AuthenticationAuthorizationService.class);
    private final ConfigurationService configurationService;
    private final StateStorageService stateStorageService;
    private final OrchestrationAuthorizationService orchestrationAuthorizationService;
    private final TokenValidationService tokenValidationService;
    private final AuthFrontend authFrontend;
    private final NowHelper.NowClock nowClock;
    public static final String AUTHENTICATION_STATE_STORAGE_PREFIX = "auth-state:";
    public static final List<ErrorObject> reauthErrors =
            List.of(OIDCError.LOGIN_REQUIRED, OAuth2Error.ACCESS_DENIED);
    public static final String GOOGLE_ANALYTICS_QUERY_PARAMETER_KEY = "result";

    public AuthenticationAuthorizationService(
            ConfigurationService configurationService, StateStorageService stateStorageService) {
        this(
                configurationService,
                stateStorageService,
                new OrchestrationAuthorizationService(configurationService),
                new TokenValidationService(
                        new JwksService(
                                configurationService,
                                new KmsConnectionService(configurationService)),
                        configurationService),
                new AuthFrontend(configurationService),
                new NowHelper.NowClock(Clock.systemUTC()));
    }

    public AuthenticationAuthorizationService(
            ConfigurationService configurationService,
            StateStorageService stateStorageService,
            OrchestrationAuthorizationService orchestrationAuthorizationService,
            TokenValidationService tokenValidationService,
            AuthFrontend authFrontend,
            NowHelper.NowClock nowClock) {
        this.configurationService = configurationService;
        this.stateStorageService = stateStorageService;
        this.orchestrationAuthorizationService = orchestrationAuthorizationService;
        this.tokenValidationService = tokenValidationService;
        this.authFrontend = authFrontend;
        this.nowClock = nowClock;
    }

    public void validateRequest(
            Map<String, String> queryParams, String sessionId, boolean reauthRequested)
            throws AuthenticationCallbackValidationException {
        LOG.info("Validating authentication callback request");
        if (queryParams == null || queryParams.isEmpty()) {
            LOG.warn("No query parameters in authentication callback request");
            throw new AuthenticationCallbackValidationException();
        }
        if (queryParams.containsKey("error")) {
            LOG.warn("Error response found in authentication callback request");
            var reauthError =
                    reauthErrors.stream()
                            .filter(error -> error.getCode().equals(queryParams.get("error")))
                            .findFirst();
            if (reauthError.isPresent()) {
                throw new AuthenticationCallbackValidationException(reauthError.get(), true);
            } else if (configurationService.isSingleFactorAccountDeletionEnabled()
                    && SFAD_ERROR.toString().equals(queryParams.get("error"))) {
                if (!reauthRequested) {
                    LOG.info("Performing single factor account deletion on an auth journey");
                    return;
                } else {
                    LOG.warn("Cannot perform single factor account deletion on a reauth journey");
                    throw new AuthenticationCallbackValidationException();
                }

            } else {
                throw new AuthenticationCallbackValidationException();
            }
        }
        if (!queryParams.containsKey("state") || queryParams.get("state").isEmpty()) {
            LOG.warn("No state param found in authentication callback request query parameters");
            throw new AuthenticationCallbackValidationException();
        }
        if (!isStateValid(sessionId, queryParams.get("state"))) {
            LOG.warn("Authentication callback request state is invalid");
            throw new AuthenticationCallbackValidationException(
                    new ErrorObject(
                            ACCESS_DENIED_CODE,
                            "Access denied for security reasons, a new authentication request may be successful"));
        }
        if (!queryParams.containsKey("code") || queryParams.get("code").isEmpty()) {
            LOG.warn("No code param found in authentication callback request query parameters");
            throw new AuthenticationCallbackValidationException();
        }
        LOG.info("Authentication callback request passed validation");
    }

    private boolean isStateValid(String sessionId, String responseState) {
        var valueFromDynamo =
                stateStorageService
                        .getState(AUTHENTICATION_STATE_STORAGE_PREFIX + sessionId)
                        .map(StateItem::getState);
        if (valueFromDynamo.isEmpty()) {
            LOG.info("No Authentication state found in Dynamo");
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

    public AuthorizationRequest generateAuthRedirectRequest(
            String sessionId,
            String clientSessionId,
            AuthenticationRequest authenticationRequest,
            ClientRegistry client,
            boolean reauthRequested,
            VectorOfTrust requestedVtr,
            Optional<String> previousSessionId,
            OrchSessionItem orchSession)
            throws AuthenticationAuthorisationRequestException {
        LOG.info("Redirecting");

        Optional<Prompt.Type> prompt =
                Objects.nonNull(authenticationRequest.getPrompt())
                                && authenticationRequest.getPrompt().contains(Prompt.Type.LOGIN)
                        ? Optional.of(Prompt.Type.LOGIN)
                        : Optional.empty();

        var googleAnalyticsOpt =
                getCustomParameterOpt(authenticationRequest, GOOGLE_ANALYTICS_QUERY_PARAMETER_KEY);

        var redirectURI = authFrontend.authorizeURI(prompt, googleAnalyticsOpt).toString();

        EncryptedJWT encryptedJWT;
        encryptedJWT =
                constructRequestJWT(
                        sessionId,
                        clientSessionId,
                        authenticationRequest,
                        client,
                        reauthRequested,
                        requestedVtr,
                        previousSessionId,
                        orchSession);

        return new AuthorizationRequest.Builder(
                        new ResponseType(ResponseType.Value.CODE),
                        new ClientID(configurationService.getOrchestrationClientId()))
                .endpointURI(URI.create(redirectURI))
                .requestObject(encryptedJWT)
                .build();
    }

    private EncryptedJWT constructRequestJWT(
            String sessionId,
            String clientSessionId,
            AuthenticationRequest authenticationRequest,
            ClientRegistry client,
            boolean reauthRequested,
            VectorOfTrust requestedVtr,
            Optional<String> previousSessionId,
            OrchSessionItem orchSession)
            throws AuthenticationAuthorisationRequestException {
        var jwtID = IdGenerator.generate();
        var expiryDate = nowClock.nowPlus(3, ChronoUnit.MINUTES);
        var rpSectorIdentifierHost =
                ClientSubjectHelper.getSectorIdentifierForClient(
                        client, configurationService.getInternalSectorURI());
        var state = new State();
        orchestrationAuthorizationService.storeState(sessionId, clientSessionId, state);

        String reauthSub = null;
        String reauthSid = null;
        if (reauthRequested) {
            try {
                SignedJWT reauthIdToken = getReauthIdToken(authenticationRequest);
                reauthSub = reauthIdToken.getJWTClaimsSet().getSubject();
                reauthSid = reauthIdToken.getJWTClaimsSet().getStringClaim("sid");
            } catch (java.text.ParseException e) {
                LOG.warn("Unable to parse id_token_hint SignedJWT into claims");
                throw new RuntimeException("Invalid id_token_hint");
            }
        }

        var cookieConsentOpt = getCustomParameterOpt(authenticationRequest, "cookie_consent");
        var gaOpt = getCustomParameterOpt(authenticationRequest, "_ga");
        var levelOfConfidenceOpt = Optional.ofNullable(requestedVtr.getLevelOfConfidence());
        var isIdentityRequired =
                identityRequired(
                        authenticationRequest.toParameters(),
                        client.isIdentityVerificationSupported(),
                        configurationService.isIdentityEnabled());
        var channel =
                getCustomParameterOpt(authenticationRequest, "channel")
                        .orElse(client.getChannel())
                        .toLowerCase();
        var claimsBuilder =
                new JWTClaimsSet.Builder()
                        .issuer(configurationService.getOrchestrationClientId())
                        .audience(authFrontend.baseURI().toString())
                        .expirationTime(expiryDate)
                        .issueTime(nowClock.now())
                        .notBeforeTime(nowClock.now())
                        .jwtID(jwtID)
                        .claim("rp_client_id", client.getClientID())
                        .claim("rp_sector_host", rpSectorIdentifierHost)
                        .claim("rp_redirect_uri", authenticationRequest.getRedirectionURI())
                        .claim("rp_state", authenticationRequest.getState().getValue())
                        .claim("client_name", client.getClientName())
                        .claim("cookie_consent_shared", client.isCookieConsentShared())
                        .claim("is_one_login_service", client.isOneLoginService())
                        .claim("service_type", client.getServiceType())
                        .claim("govuk_signin_journey_id", clientSessionId)
                        .claim(
                                "requested_credential_strength",
                                requestedVtr.getCredentialTrustLevel().getValue())
                        .claim("state", state.getValue())
                        .claim("client_id", configurationService.getOrchestrationClientId())
                        .claim("redirect_uri", configurationService.getOrchestrationRedirectURI())
                        .claim("reauthenticate", reauthSub)
                        .claim("previous_govuk_signin_journey_id", reauthSid)
                        .claim("channel", channel)
                        .claim("authenticated", orchSession.getAuthenticated())
                        .claim("scope", authenticationRequest.getScope().toString())
                        .claim("login_hint", authenticationRequest.getLoginHint())
                        .claim("is_smoke_test", client.isSmokeTest())
                        .claim("subject_type", client.getSubjectType())
                        .claim("is_identity_verification_required", isIdentityRequired);

        previousSessionId.ifPresent(id -> claimsBuilder.claim("previous_session_id", id));
        gaOpt.ifPresent(ga -> claimsBuilder.claim("_ga", ga));
        cookieConsentOpt.ifPresent(
                cookieConsent -> claimsBuilder.claim("cookie_consent", cookieConsent));
        levelOfConfidenceOpt.ifPresent(
                levelOfConfidence ->
                        claimsBuilder.claim(
                                "requested_level_of_confidence", levelOfConfidence.getValue()));

        var claimsSetRequest =
                constructAdditionalAuthenticationClaims(client, authenticationRequest);
        claimsSetRequest.ifPresent(t -> claimsBuilder.claim("claim", t.toJSONString()));
        return orchestrationAuthorizationService.getSignedAndEncryptedJWT(claimsBuilder.build());
    }

    private Optional<OIDCClaimsRequest> constructAdditionalAuthenticationClaims(
            ClientRegistry clientRegistry, AuthenticationRequest authenticationRequest) {
        LOG.info("Constructing additional authentication claims");
        var identityRequired =
                identityRequired(
                        authenticationRequest.toParameters(),
                        clientRegistry.isIdentityVerificationSupported(),
                        configurationService.isIdentityEnabled());

        var amScopePresent =
                requestedScopesContain(CustomScopeValue.ACCOUNT_MANAGEMENT, authenticationRequest);
        var govukAccountScopePresent =
                requestedScopesContain(CustomScopeValue.GOVUK_ACCOUNT, authenticationRequest);
        var phoneScopePresent = requestedScopesContain(OIDCScopeValue.PHONE, authenticationRequest);
        var emailScopePresent = requestedScopesContain(OIDCScopeValue.EMAIL, authenticationRequest);

        var claimsSet = new HashSet<AuthUserInfoClaims>();
        claimsSet.add(AuthUserInfoClaims.EMAIL);
        claimsSet.add(AuthUserInfoClaims.LOCAL_ACCOUNT_ID);
        claimsSet.add(AuthUserInfoClaims.VERIFIED_MFA_METHOD_TYPE);
        claimsSet.add(AuthUserInfoClaims.UPLIFT_REQUIRED);
        claimsSet.add(AuthUserInfoClaims.ACHIEVED_CREDENTIAL_STRENGTH);
        if (identityRequired) {
            LOG.info(
                    "Identity is required. Adding the salt, email_verified and phone_number claims");
            claimsSet.add(AuthUserInfoClaims.SALT);
            // Email required for ID journeys for use in Face-to-Face flows
            claimsSet.add(AuthUserInfoClaims.EMAIL_VERIFIED);
            claimsSet.add(AuthUserInfoClaims.PHONE_NUMBER);
        }
        if (amScopePresent) {
            LOG.info("am scope is present. Adding the public_subject_id claim");
            claimsSet.add(AuthUserInfoClaims.PUBLIC_SUBJECT_ID);
        } else if (PUBLIC.toString().equalsIgnoreCase(clientRegistry.getSubjectType())) {
            LOG.info("client has PUBLIC subjectType. Adding the public_subject_id claim");
            claimsSet.add(AuthUserInfoClaims.PUBLIC_SUBJECT_ID);
        }

        if (govukAccountScopePresent) {
            LOG.info("govuk-account scope is present. Adding the legacy_subject_id claim");
            claimsSet.add(AuthUserInfoClaims.LEGACY_SUBJECT_ID);
        }
        if (phoneScopePresent) {
            LOG.info(
                    "phone scope is present. Adding the phone_number and phone_number_verified claim");
            claimsSet.add(AuthUserInfoClaims.PHONE_NUMBER);
            claimsSet.add(AuthUserInfoClaims.PHONE_VERIFIED);
        }
        if (emailScopePresent) {
            LOG.info("email scope is present. Adding the email_verified claim");
            claimsSet.add(AuthUserInfoClaims.EMAIL_VERIFIED);
        }

        var claimSetEntries =
                claimsSet.stream()
                        .sorted(Comparator.naturalOrder())
                        .map(claim -> new ClaimsSetRequest.Entry(claim.getValue()))
                        .toList();

        if (claimSetEntries.isEmpty()) {
            LOG.info("No additional claims to add to request");
            return Optional.empty();
        }
        var claimsSetRequest = new ClaimsSetRequest(claimSetEntries);
        return Optional.of(new OIDCClaimsRequest().withUserInfoClaimsRequest(claimsSetRequest));
    }

    private boolean requestedScopesContain(
            Scope.Value scope, AuthenticationRequest authenticationRequest) {
        return authenticationRequest.getScope().toStringList().contains(scope.getValue());
    }

    private SignedJWT getReauthIdToken(AuthenticationRequest authenticationRequest)
            throws AuthenticationAuthorisationRequestException {
        boolean isTokenSignatureValid =
                segmentedFunctionCall(
                        "isTokenSignatureValid",
                        () ->
                                tokenValidationService.isTokenSignatureValid(
                                        authenticationRequest
                                                .getCustomParameter("id_token_hint")
                                                .get(0)));
        if (!isTokenSignatureValid) {
            LOG.warn("Unable to validate ID token signature");
            throw new AuthenticationAuthorisationRequestException(
                    "Unable to validate id_token_hint");
        }

        SignedJWT idToken;
        String aud;
        try {
            idToken =
                    SignedJWT.parse(
                            authenticationRequest.getCustomParameter("id_token_hint").get(0));
            aud = idToken.getJWTClaimsSet().getAudience().stream().findFirst().orElse(null);
        } catch (java.text.ParseException e) {
            LOG.warn("Unable to parse id_token_hint into SignedJWT");
            throw new AuthenticationAuthorisationRequestException("Invalid id_token_hint");
        }

        if (aud == null || !aud.equals(authenticationRequest.getClientID().getValue())) {
            LOG.warn("Audience on id_token_hint does not match client ID");
            throw new AuthenticationAuthorisationRequestException(
                    "Invalid id_token_hint for client");
        }
        return idToken;
    }
}
