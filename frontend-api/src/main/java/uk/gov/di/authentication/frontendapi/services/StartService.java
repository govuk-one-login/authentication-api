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
import java.util.Objects;
import java.util.Optional;

import static java.util.function.Predicate.not;

public class StartService {

    private final ClientService clientService;
    private final DynamoService dynamoService;
    private final SessionService sessionService;
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

    public UserContext buildUserContext(Session session, AuthSessionItem authSession) {
        var builder = UserContext.builder(session).withAuthSession(authSession);
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
            String serviceType,
            String clientName,
            List<String> scopes,
            URI redirectURI,
            State state,
            boolean isCookieConsentShared,
            boolean isOneLoginService) {
        var clientInfo =
                new ClientStartInfo(
                        clientName,
                        scopes,
                        serviceType,
                        isCookieConsentShared,
                        redirectURI,
                        state,
                        isOneLoginService);
        LOG.info(
                "Found ClientStartInfo for ClientName: {} Scopes: {} ServiceType: {}",
                clientName,
                scopes,
                serviceType);

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
            boolean upliftRequired,
            boolean identityRequiredFromFrontend) {
        var identityRequired = false;
        var clientRegistry = userContext.getClient().orElseThrow();
        identityRequired =
                IdentityHelper.identityRequired(
                        levelOfConfidence,
                        clientRegistry.isIdentityVerificationSupported(),
                        identityEnabled);

        LOG.info(
                "isIdentityVerificationRequired is equal {}",
                identityRequired == identityRequiredFromFrontend);

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

    public String getCookieConsentValue(String cookieConsentValue, boolean isCookieConsentShared) {
        if (validCookieConsentValueIsPresent(cookieConsentValue) && isCookieConsentShared) {
            LOG.info("Sharing cookie_consent");
            return cookieConsentValue;
        }
        return null;
    }

    public boolean isUserProfileEmpty(AuthSessionItem authSession) {
        return Optional.ofNullable(authSession.getEmailAddress())
                .flatMap(dynamoService::getUserProfileByEmailMaybe)
                .isEmpty();
    }

    public boolean isUpliftRequired(
            CredentialTrustLevel requestedCredentialStrength,
            CredentialTrustLevel currentCredentialStrength) {
        if (Objects.isNull(currentCredentialStrength)) {
            return false;
        }
        return currentCredentialStrength.isLowerThan(requestedCredentialStrength);
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

    private boolean validCookieConsentValueIsPresent(String cookieConsent) {
        return cookieConsent != null
                && List.of(COOKIE_CONSENT_ACCEPT, COOKIE_CONSENT_REJECT, COOKIE_CONSENT_NOT_ENGAGED)
                        .contains(cookieConsent);
    }
}
