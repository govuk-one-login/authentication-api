package uk.gov.di.orchestration.shared.state;

import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.entity.OrchClientSessionItem;
import uk.gov.di.orchestration.shared.entity.OrchSessionItem;
import uk.gov.di.orchestration.shared.helpers.LocaleHelper.SupportedLanguage;

import java.util.Optional;

public class UserContext {
    private final String sessionId;
    private final Optional<ClientRegistry> client;
    private final OrchClientSessionItem orchClientSession;
    private final SupportedLanguage userLanguage;
    private final String clientSessionId;
    private final OrchSessionItem orchSession;
    private final String clientId;

    protected UserContext(
            String sessionId,
            Optional<ClientRegistry> client,
            OrchClientSessionItem orchClientSession,
            SupportedLanguage userLanguage,
            String clientSessionId,
            OrchSessionItem orchSession,
            String clientId) {
        this.sessionId = sessionId;
        this.client = client;
        this.orchClientSession = orchClientSession;
        this.userLanguage = userLanguage;
        this.clientSessionId = clientSessionId;
        this.orchSession = orchSession;
        this.clientId = clientId;
    }

    public String getSessionId() {
        return sessionId;
    }

    public Optional<ClientRegistry> getClient() {
        return client;
    }

    public String getClientId() {
        return clientId;
    }

    public String getClientName() {
        return getClient().map(ClientRegistry::getClientName).orElse("");
    }

    public OrchClientSessionItem getOrchClientSession() {
        return orchClientSession;
    }

    public SupportedLanguage getUserLanguage() {
        return userLanguage;
    }

    public String getClientSessionId() {
        return clientSessionId;
    }

    public OrchSessionItem getOrchSession() {
        return orchSession;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private String sessionId;
        private Optional<ClientRegistry> client = Optional.empty();
        private OrchClientSessionItem orchClientSession;
        private SupportedLanguage userLanguage;
        private String clientSessionId;
        private OrchSessionItem orchSession;
        private String clientId;

        protected Builder() {}

        public Builder withSessionId(String sessionId) {
            this.sessionId = sessionId;
            return this;
        }

        public Builder withClient(ClientRegistry client) {
            return withClient(Optional.of(client));
        }

        public Builder withClient(Optional<ClientRegistry> client) {
            this.client = client;
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

        public Builder withUserLanguage(SupportedLanguage userLanguage) {
            this.userLanguage = userLanguage;
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

        public UserContext build() {
            return new UserContext(
                    sessionId,
                    client,
                    orchClientSession,
                    userLanguage,
                    clientSessionId,
                    orchSession,
                    clientId);
        }
    }
}
