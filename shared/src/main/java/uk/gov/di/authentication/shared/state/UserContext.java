package uk.gov.di.authentication.shared.state;

import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.UserProfile;

import java.util.Optional;

public record UserContext(
        AuthSessionItem authSessionItem,
        Optional<UserProfile> userProfile,
        String clientSessionId,
        String txmaAuditEncoded) {}
