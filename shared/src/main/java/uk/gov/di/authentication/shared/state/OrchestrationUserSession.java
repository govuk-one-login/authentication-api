package uk.gov.di.authentication.shared.state;

import org.jetbrains.annotations.Nullable;

public class OrchestrationUserSession {
    @Nullable private final String clientId;
    private final String clientSessionId;

    protected OrchestrationUserSession(@Nullable String clientId, String clientSessionId) {
        this.clientId = clientId;
        this.clientSessionId = clientSessionId;
    }

    public @Nullable String getClientId() {
        return clientId;
    }

    public String getClientSessionId() {
        return clientSessionId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private String clientId;
        private String clientSessionId;

        protected Builder() {}

        public Builder withClientId(String clientId) {
            this.clientId = clientId;
            return this;
        }

        public Builder withClientSessionId(String clientSessionId) {
            this.clientSessionId = clientSessionId;
            return this;
        }

        public OrchestrationUserSession build() {
            return new OrchestrationUserSession(clientId, clientSessionId);
        }
    }
}
