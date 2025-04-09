package uk.gov.di.authentication.frontendapi.services;

import com.nimbusds.oauth2.sdk.id.State;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.frontendapi.entity.ClientStartInfo;
import uk.gov.di.authentication.frontendapi.entity.UserStartInfo;
import uk.gov.di.authentication.shared.conditions.IdentityHelper;
import uk.gov.di.authentication.shared.conditions.MfaHelper;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.CredentialTrustLevel;
import uk.gov.di.authentication.shared.entity.LevelOfConfidence;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.UserCredentials;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethod;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.exceptions.ClientNotFoundException;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.shared.state.UserContext;

import java.net.URI;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import static java.lang.String.format;
import static java.util.function.Predicate.not;
import static uk.gov.di.authentication.frontendapi.entity.RequestParameters.COOKIE_CONSENT;
import static uk.gov.di.authentication.frontendapi.entity.RequestParameters.GA;

public class StartService {

    private final ClientService clientService;
    private final DynamoService dynamoService;
    private final SessionService sessionService;
    private static final String CLIENT_ID_PARAM = "client_id";
    public static final String COOKIE_CONSENT_ACCEPT = "accept";
    public static final String COOKIE_CONSENT_REJECT = "reject";
    public static final String COOKIE_CONSENT_NOT_ENGAGED = "not-engaged";
    private static final Logger LOG = LogManager.getLogger(StartService.class);

    public StartService(
            ClientService clientService,
            DynamoService dynamoService,
            SessionService sessionService) {
        this.clientService = clientService;
        this.dynamoService = dynamoService;
        this.sessionService = sessionService;
    }

    public UserContext buildUserContext(
            Session session, ClientSession clientSession, AuthSessionItem authSession) {
        var builder =
                UserContext.builder(session)
                        .withClientSession(clientSession)
                        .withAuthSession(authSession);
        UserContext userContext;
        try {
            var clientRegistry = getClient(authSession.getClientId());
            Optional.of(authSession)
                    .map(AuthSessionItem::getEmailAddress)
                    .flatMap(dynamoService::getUserProfileByEmailMaybe)
                    .ifPresent(
                            t ->
                                    builder.withUserProfile(t)
                                            .withUserCredentials(
                                                    Optional.of(
                                                            dynamoService
                                                                    .getUserCredentialsFromEmail(
                                                                            authSession
                                                                                    .getEmailAddress()))));
            userContext = builder.withClient(clientRegistry).build();
        } catch (ClientNotFoundException e) {
            LOG.error("Error creating UserContext");
            throw new RuntimeException("Error when creating UserContext", e);
        }
        return userContext;
    }

    public ClientStartInfo buildClientStartInfo(
            ClientRegistry clientRegistry, List<String> scopes, URI redirectURI, State state) {
        var clientInfo =
                new ClientStartInfo(
                        clientRegistry.getClientName(),
                        scopes,
                        clientRegistry.getServiceType(),
                        clientRegistry.isCookieConsentShared(),
                        redirectURI,
                        state,
                        clientRegistry.isOneLoginService());
        LOG.info(
                "Found ClientStartInfo for ClientName: {} Scopes: {} ServiceType: {}",
                clientRegistry.getClientName(),
                scopes,
                clientRegistry.getServiceType());

        return clientInfo;
    }

    public UserStartInfo buildUserStartInfo(
            UserContext userContext,
            LevelOfConfidence levelOfConfidence,
            String cookieConsent,
            String gaTrackingId,
            boolean identityEnabled,
            boolean reauthenticate,
            boolean isBlockedForReauth,
            boolean isAuthenticated,
            boolean upliftRequired) {
        var identityRequired = false;
        var clientRegistry = userContext.getClient().orElseThrow();
        identityRequired =
                IdentityHelper.identityRequired(
                        levelOfConfidence,
                        clientRegistry.isIdentityVerificationSupported(),
                        identityEnabled);

        var userIsAuthenticated = isAuthenticated && !reauthenticate;

        LOG.info(
                "Found UserStartInfo for Authenticated: {} UpliftRequired: {} IdentityRequired: {}. CookieConsent: {}. GATrackingId: {}. IsBlockedForReauth: {}",
                userIsAuthenticated,
                upliftRequired,
                identityRequired,
                cookieConsent,
                gaTrackingId,
                isBlockedForReauth);

        return new UserStartInfo(
                upliftRequired,
                identityRequired,
                userIsAuthenticated,
                cookieConsent,
                gaTrackingId,
                getMfaMethodType(userContext),
                isBlockedForReauth);
    }

    private boolean authApp(UserContext userContext) {
        return userContext.getUserCredentials().stream()
                .map(UserCredentials::getMfaMethods)
                .filter(Objects::nonNull)
                .filter(not(List::isEmpty))
                .flatMap(Collection::stream)
                .filter(MFAMethod::isMethodVerified)
                .map(MFAMethod::getMfaMethodType)
                .anyMatch(MFAMethodType.AUTH_APP.getValue()::equals);
    }

    public String getGATrackingId(Map<String, List<String>> authRequestParameters) {
        if (authRequestParameters.containsKey(GA)) {
            String gaId = authRequestParameters.get(GA).get(0);
            LOG.info("GA value present in request {}", gaId);
            return gaId;
        }
        return null;
    }

    public String getCookieConsentValue(
            Map<String, List<String>> authRequestParameters, String clientID) {
        try {
            if (validCookieConsentValueIsPresent(authRequestParameters)
                    && isClientCookieConsentShared(clientID)) {
                LOG.info("Sharing cookie_consent");
                return authRequestParameters.get(COOKIE_CONSENT).get(0);
            }
            return null;
        } catch (ClientNotFoundException e) {
            throw new RuntimeException("Client not found", e);
        }
    }

    public boolean isUserProfileEmpty(AuthSessionItem authSession) {
        return Optional.ofNullable(authSession.getEmailAddress())
                .flatMap(dynamoService::getUserProfileByEmailMaybe)
                .isEmpty();
    }

    public boolean isUpliftRequired(
            ClientSession clientSession, CredentialTrustLevel currentCredentialStrength) {
        if (Objects.isNull(currentCredentialStrength)) {
            return false;
        }
        return (currentCredentialStrength.compareTo(
                        clientSession.getEffectiveVectorOfTrust().getCredentialTrustLevel())
                < 0);
    }

    public ClientRegistry getClient(String clientId) throws ClientNotFoundException {
        return clientService
                .getClient(clientId)
                .orElseThrow(
                        () ->
                                new ClientNotFoundException(
                                        "Could not find client for start service"));
    }

    public MFAMethodType getMfaMethodType(UserContext userContext) {
        var maybeUserProfile = userContext.getUserProfile();
        if (maybeUserProfile.isEmpty()) {
            return null;
        }

        var userProfile = maybeUserProfile.get();
        if (userProfile.getMfaMethodsMigrated()) {
            var maybeUserCredentials = userContext.getUserCredentials();
            if (maybeUserCredentials.isPresent()) {
                var userCredentials = maybeUserCredentials.get();
                var defaultMfaMethod =
                        MfaHelper.getDefaultMfaMethodForMigratedUser(userCredentials);
                if (defaultMfaMethod.isPresent()) {
                    return MFAMethodType.valueOf(defaultMfaMethod.get().getMfaMethodType());
                } else {
                    LOG.error(
                            "Unexpected error getting default mfa method for user: no default method exists");
                    return MFAMethodType.NONE;
                }
            } else {
                LOG.error(
                        "Attempted to get default mfa method for migrated user without user credentials");
                return MFAMethodType.NONE;
            }
        }
        if (userContext.getUserProfile().filter(UserProfile::isPhoneNumberVerified).isPresent()) {
            return MFAMethodType.SMS;
        } else if (authApp(userContext)) {
            return MFAMethodType.AUTH_APP;
        } else return null;
    }

    private boolean isClientCookieConsentShared(String clientID) throws ClientNotFoundException {
        return clientService
                .getClient(clientID)
                .map(ClientRegistry::isCookieConsentShared)
                .orElseThrow(
                        () ->
                                new ClientNotFoundException(
                                        format(
                                                "Could not find client for clientID: %s",
                                                clientID)));
    }

    private boolean validCookieConsentValueIsPresent(
            Map<String, List<String>> authRequestParameters) {
        return authRequestParameters.containsKey(COOKIE_CONSENT)
                && !authRequestParameters.get(COOKIE_CONSENT).isEmpty()
                && authRequestParameters.get(COOKIE_CONSENT).get(0) != null
                && List.of(COOKIE_CONSENT_ACCEPT, COOKIE_CONSENT_REJECT, COOKIE_CONSENT_NOT_ENGAGED)
                        .contains(authRequestParameters.get(COOKIE_CONSENT).get(0));
    }
}
