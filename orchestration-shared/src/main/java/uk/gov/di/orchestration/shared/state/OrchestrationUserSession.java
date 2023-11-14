package uk.gov.di.orchestration.shared.state;

import org.jetbrains.annotations.Nullable;
import uk.gov.di.orchestration.shared.entity.ClientSession;
import uk.gov.di.orchestration.shared.entity.Session;

public class OrchestrationUserSession {
    private final Session session;
    @Nullable private final String clientId;
    @Nullable private final ClientSession clientSession;
    private final String clientSessionId;

    protected OrchestrationUserSession(
            Session session,
            @Nullable String clientId,
            @Nullable ClientSession clientSession,
            String clientSessionId) {
        this.session = session;
        this.clientId = clientId;
        this.clientSession = clientSession;
        this.clientSessionId = clientSessionId;
    }

    public Session getSession() {
        return session;
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

    public static Builder builder(Session session) {
        return new Builder(session);
    }

    public static class Builder {
        private Session session;
        private String clientId;
        private ClientSession clientSession;
        private String clientSessionId;

        protected Builder(Session session) {
            this.session = session;
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

        public OrchestrationUserSession build() {
            return new OrchestrationUserSession(session, clientId, clientSession, clientSessionId);
        }
    }
}
