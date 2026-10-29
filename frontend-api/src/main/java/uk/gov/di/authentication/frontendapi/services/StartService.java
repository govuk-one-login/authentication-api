package uk.gov.di.authentication.frontendapi.services;

import com.nimbusds.oauth2.sdk.id.State;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.frontendapi.entity.ClientStartInfo;
import uk.gov.di.authentication.frontendapi.entity.UserDetails;
import uk.gov.di.authentication.frontendapi.entity.UserStartInfo;
import uk.gov.di.authentication.shared.conditions.MfaHelper;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.CredentialTrustLevel;
import uk.gov.di.authentication.shared.entity.UserCredentials;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethod;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.services.DynamoService;

import java.net.URI;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import static java.util.function.Predicate.not;

public class StartService {

    private final DynamoService dynamoService;
    public static final String COOKIE_CONSENT_ACCEPT = "accept";
    public static final String COOKIE_CONSENT_REJECT = "reject";
    public static final String COOKIE_CONSENT_NOT_ENGAGED = "not-engaged";
    private static final Logger LOG = LogManager.getLogger(StartService.class);

    public StartService(DynamoService dynamoService) {
        this.dynamoService = dynamoService;
    }

    public UserDetails getUserDetails(AuthSessionItem authSession) {
        return Optional.of(authSession)
                .map(AuthSessionItem::getEmailAddress)
                .flatMap(dynamoService::getUserProfileByEmailMaybe)
                .map(
                        userProfile -> {
                            var userCredentials =
                                    Optional.ofNullable(
                                            dynamoService.getUserCredentialsFromEmail(
                                                    authSession.getEmailAddress()));
                            return new UserDetails(Optional.of(userProfile), userCredentials);
                        })
                .orElse(new UserDetails(Optional.empty(), Optional.empty()));
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
            UserDetails userDetails,
            String cookieConsent,
            String gaTrackingId,
            boolean identityRequired,
            boolean reauthenticate,
            boolean isBlockedForReauth,
            boolean isAuthenticated,
            boolean upliftRequired,
            boolean isMfaRequired) {

        var userIsAuthenticated = isAuthenticated && !reauthenticate;

        LOG.info(
                "Found UserStartInfo for Authenticated: {} UpliftRequired: {} IdentityRequired: {}. CookieConsent: {}. GATrackingId: {}. IsBlockedForReauth: {}. IsMfaRequired: {}.",
                userIsAuthenticated,
                upliftRequired,
                identityRequired,
                cookieConsent,
                gaTrackingId,
                isBlockedForReauth,
                isMfaRequired);

        return new UserStartInfo(
                upliftRequired,
                identityRequired,
                userIsAuthenticated,
                cookieConsent,
                gaTrackingId,
                getMfaMethodType(userDetails),
                isBlockedForReauth,
                isMfaRequired);
    }

    private boolean authApp(UserDetails userDetails) {
        return userDetails.maybeUserCredentials().stream()
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

    public MFAMethodType getMfaMethodType(UserDetails userDetails) {
        var maybeUserProfile = userDetails.maybeUserProfile();
        if (maybeUserProfile.isEmpty()) {
            return null;
        }
        var userProfile = maybeUserProfile.get();

        if (userProfile.isMfaMethodsMigrated()) {
            return getMfaMethodForMigratedUser(userDetails);
        } else {
            return getMfaMethodForNonMigratedUser(userDetails);
        }
    }

    private MFAMethodType getMfaMethodForNonMigratedUser(UserDetails userDetails) {
        if (userDetails.maybeUserProfile().filter(UserProfile::isPhoneNumberVerified).isPresent()) {
            return MFAMethodType.SMS;
        } else if (authApp(userDetails)) {
            return MFAMethodType.AUTH_APP;
        } else return null;
    }

    private MFAMethodType getMfaMethodForMigratedUser(UserDetails userDetails) {
        var maybeUserCredentials = userDetails.maybeUserCredentials();
        if (maybeUserCredentials.isPresent()) {
            var userCredentials = maybeUserCredentials.get();
            var defaultMfaMethod = MfaHelper.getDefaultMfaMethodForMigratedUser(userCredentials);
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

    private boolean validCookieConsentValueIsPresent(String cookieConsent) {
        return cookieConsent != null
                && List.of(COOKIE_CONSENT_ACCEPT, COOKIE_CONSENT_REJECT, COOKIE_CONSENT_NOT_ENGAGED)
                        .contains(cookieConsent);
    }
}
