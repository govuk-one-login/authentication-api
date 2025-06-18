package uk.gov.di.authentication.oidc.entity;

import com.google.gson.annotations.Expose;
import uk.gov.di.orchestration.shared.validation.Required;

public record GlobalLogoutMessage(
        @Expose @Required String clientId,
        @Expose @Required String eventId,
        @Expose @Required String sessionId,
        @Expose @Required String clientSessionId,
        @Expose @Required String internalCommonSubjectId,
        @Expose @Required String persistentSessionId,
        @Expose @Required String ipAddress) {}
