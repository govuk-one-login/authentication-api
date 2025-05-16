package uk.gov.di.authentication.shared.state;

import org.jetbrains.annotations.Nullable;
import uk.gov.di.authentication.shared.entity.Session;

public class OrchestrationUserSession {
    private final Session session;
    @Nullable private final String clientId;
    private final String clientSessionId;

    protected OrchestrationUserSession(
            Session session, @Nullable String clientId, String clientSessionId) {
        this.session = session;
        this.clientId = clientId;
        this.clientSessionId = clientSessionId;
    }

    public Session getSession() {
        return session;
    }

    public @Nullable String getClientId() {
        return clientId;
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
        private String clientSessionId;

        protected Builder(Session session) {
            this.session = session;
        }

        public Builder withClientId(String clientId) {
            this.clientId = clientId;
            return this;
        }

        public Builder withClientSessionId(String clientSessionId) {
            this.clientSessionId = clientSessionId;
            return this;
        }

        public OrchestrationUserSession build() {
            return new OrchestrationUserSession(session, clientId, clientSessionId);
        }
    }
}
