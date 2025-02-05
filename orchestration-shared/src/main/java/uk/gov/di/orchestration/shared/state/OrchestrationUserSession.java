package uk.gov.di.orchestration.shared.state;

import org.jetbrains.annotations.Nullable;
import uk.gov.di.orchestration.shared.entity.ClientSession;
import uk.gov.di.orchestration.shared.entity.OrchSessionItem;
import uk.gov.di.orchestration.shared.entity.Session;

public class OrchestrationUserSession {
    private final Session session;
    private final String sessionId;
    @Nullable private final String clientId;
    @Nullable private final ClientSession clientSession;
    private final String clientSessionId;
    private final OrchSessionItem orchSessionItem;

    protected OrchestrationUserSession(
            Session session,
            String sessionId,
            @Nullable String clientId,
            @Nullable ClientSession clientSession,
            String clientSessionId,
            OrchSessionItem orchSession) {
        this.session = session;
        this.sessionId = sessionId;
        this.clientId = clientId;
        this.clientSession = clientSession;
        this.clientSessionId = clientSessionId;
        this.orchSessionItem = orchSession;
    }

    public Session getSession() {
        return session;
    }

    public String getSessionId() {
        return sessionId;
    }

    public @Nullable String getClientId() {
        return clientId;
    }

    public @Nullable ClientSession getClientSession() {
        return clientSession;
    }

    public String getClientSessionId() {
        return clientSessionId;
    }

    public OrchSessionItem getOrchSession() {
        return orchSessionItem;
    }

    public static Builder builder(Session session) {
        return new Builder(session);
    }

    public static class Builder {
        private Session session;
        private String sessionId;
        private String clientId;
        private ClientSession clientSession;
        private String clientSessionId;
        private OrchSessionItem orchSession;

        protected Builder(Session session) {
            this.session = session;
        }

        public Builder withSessionId(String sessionId) {
            this.sessionId = sessionId;
            return this;
        }

        public Builder withClientId(String clientId) {
            this.clientId = clientId;
            return this;
        }

        public Builder withClientSession(ClientSession clientSession) {
            this.clientSession = clientSession;
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
                    session, sessionId, clientId, clientSession, clientSessionId, orchSession);
        }
    }
}
