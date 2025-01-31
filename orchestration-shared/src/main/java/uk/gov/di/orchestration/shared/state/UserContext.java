package uk.gov.di.orchestration.shared.state;

import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.entity.ClientSession;
import uk.gov.di.orchestration.shared.entity.Session;
import uk.gov.di.orchestration.shared.entity.UserCredentials;
import uk.gov.di.orchestration.shared.entity.UserProfile;
import uk.gov.di.orchestration.shared.helpers.LocaleHelper.SupportedLanguage;

import java.util.Optional;

public class UserContext {
    private final Session session;
    private final String sessionId;
    private final Optional<UserProfile> userProfile;
    private final Optional<UserCredentials> userCredentials;
    private final boolean userAuthenticated;
    private final Optional<ClientRegistry> client;
    private final ClientSession clientSession;
    private final SupportedLanguage userLanguage;
    private final String clientSessionId;

    protected UserContext(
            Session session,
            String sessionId,
            Optional<UserProfile> userProfile,
            Optional<UserCredentials> userCredentials,
            boolean userAuthenticated,
            Optional<ClientRegistry> client,
            ClientSession clientSession,
            SupportedLanguage userLanguage,
            String clientSessionId) {
        this.session = session;
        this.sessionId = sessionId;
        this.userProfile = userProfile;
        this.userCredentials = userCredentials;
        this.userAuthenticated = userAuthenticated;
        this.client = client;
        this.clientSession = clientSession;
        this.userLanguage = userLanguage;
        this.clientSessionId = clientSessionId;
    }

    public Session getSession() {
        return session;
    }

    public String getSessionId() {
        return sessionId;
    }

    public Optional<UserProfile> getUserProfile() {
        return userProfile;
    }

    public Optional<UserCredentials> getUserCredentials() {
        return userCredentials;
    }

    public boolean isUserAuthenticated() {
        return userAuthenticated;
    }

    public Optional<ClientRegistry> getClient() {
        return client;
    }

    public String getClientId() {
        return getClient().map(ClientRegistry::getClientID).orElse("");
    }

    public String getClientName() {
        return getClient().map(ClientRegistry::getClientName).orElse("");
    }

    public ClientSession getClientSession() {
        return clientSession;
    }

    public SupportedLanguage getUserLanguage() {
        return userLanguage;
    }

    public String getClientSessionId() {
        return clientSessionId;
    }

    public static Builder builder(Session session) {
        return new Builder(session);
    }

    public static class Builder {
        private Session session;
        private String sessionId;
        private Optional<UserProfile> userProfile = Optional.empty();
        private Optional<UserCredentials> userCredentials = Optional.empty();
        private boolean userAuthenticated = false;
        private Optional<ClientRegistry> client = Optional.empty();
        private ClientSession clientSession = null;
        private SupportedLanguage userLanguage;
        private String clientSessionId;

        protected Builder(Session session) {
            this.session = session;
        }

        public Builder withSessionId(String sessionId) {
            this.sessionId = sessionId;
            return this;
        }

        public Builder withUserProfile(UserProfile userProfile) {
            return withUserProfile(Optional.of(userProfile));
        }

        public Builder withUserProfile(Optional<UserProfile> userProfile) {
            this.userProfile = userProfile;
            return this;
        }

        public Builder withUserCredentials(Optional<UserCredentials> userCredentials) {
            this.userCredentials = userCredentials;
            return this;
        }

        public Builder withUserAuthenticated(boolean userAuthenticated) {
            this.userAuthenticated = userAuthenticated;
            return this;
        }

        public Builder withClient(ClientRegistry client) {
            return withClient(Optional.of(client));
        }

        public Builder withClient(Optional<ClientRegistry> client) {
            this.client = client;
            return this;
        }

        public Builder withClientSession(ClientSession clientSession) {
            this.clientSession = clientSession;
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

        public UserContext build() {
            return new UserContext(
                    session,
                    sessionId,
                    userProfile,
                    userCredentials,
                    userAuthenticated,
                    client,
                    clientSession,
                    userLanguage,
                    clientSessionId);
        }
    }
}
