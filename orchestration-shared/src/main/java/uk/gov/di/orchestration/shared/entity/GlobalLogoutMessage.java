package uk.gov.di.orchestration.shared.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.orchestration.shared.validation.Required;

public record GlobalLogoutMessage(
        @Expose @Required String clientId,
        @Expose @Required String eventId,
        @Expose @Required String sessionId,
        @Expose @Required String clientSessionId,
        @Expose @Required @SerializedName("internal_common_subject_identifier")
                String internalCommonSubjectId,
        @Expose @Required String persistentSessionId,
        @Expose @Required String ipAddress) {}
