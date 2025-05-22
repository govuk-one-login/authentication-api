package uk.gov.di.orchestration.shared.state;

import org.jetbrains.annotations.Nullable;
import uk.gov.di.orchestration.shared.entity.OrchClientSessionItem;
import uk.gov.di.orchestration.shared.entity.OrchSessionItem;

public class OrchestrationUserSession {
    private final String sessionId;
    @Nullable private final String clientId;
    @Nullable private final OrchClientSessionItem orchClientSession;
    private final String clientSessionId;
    private final OrchSessionItem orchSessionItem;

    protected OrchestrationUserSession(
            String sessionId,
            @Nullable String clientId,
            @Nullable OrchClientSessionItem orchClientSession,
            String clientSessionId,
            OrchSessionItem orchSession) {
        this.sessionId = sessionId;
        this.clientId = clientId;
        this.orchClientSession = orchClientSession;
        this.clientSessionId = clientSessionId;
        this.orchSessionItem = orchSession;
    }

    public String getSessionId() {
        return sessionId;
    }

    public @Nullable String getClientId() {
        return clientId;
    }

    public @Nullable OrchClientSessionItem getOrchClientSession() {
        return orchClientSession;
    }

    public String getClientSessionId() {
        return clientSessionId;
    }

    public OrchSessionItem getOrchSession() {
        return orchSessionItem;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private String sessionId;
        private String clientId;
        private OrchClientSessionItem orchClientSession;
        private String clientSessionId;
        private OrchSessionItem orchSession;

        protected Builder() {}

        public Builder withSessionId(String sessionId) {
            this.sessionId = sessionId;
            return this;
        }

        public Builder withClientId(String clientId) {
            this.clientId = clientId;
            return this;
        }

        public Builder withOrchClientSession(OrchClientSessionItem orchClientSession) {
            this.orchClientSession = orchClientSession;
            return this;
        }

        public Builder withClientSessionId(String clientSessionId) {
            this.clientSessionId = clientSessionId;
            return this;
        }

        public Builder withOrchSession(OrchSessionItem orchSession) {
            this.orchSession = orchSession;
            return this;
        }

        public OrchestrationUserSession build() {
            return new OrchestrationUserSession(
                    sessionId, clientId, orchClientSession, clientSessionId, orchSession);
        }
    }
}
