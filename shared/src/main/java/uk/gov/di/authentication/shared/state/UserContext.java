package uk.gov.di.authentication.shared.state;

import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.helpers.LocaleHelper.SupportedLanguage;

import java.util.Optional;

public record UserContext(
        AuthSessionItem authSessionItem,
        Optional<UserProfile> userProfile,
        SupportedLanguage userLanguage,
        String clientSessionId,
        String txmaAuditEncoded) {}
