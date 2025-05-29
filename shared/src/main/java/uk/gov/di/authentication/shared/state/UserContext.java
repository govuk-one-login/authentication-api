package uk.gov.di.authentication.shared.state;

import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.UserCredentials;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.helpers.LocaleHelper.SupportedLanguage;

import java.util.Optional;

public class UserContext {
    private final Session session;
    private final AuthSessionItem authSession;
    private final Optional<UserProfile> userProfile;
    private final Optional<UserCredentials> userCredentials;
    private final boolean userAuthenticated;
    private final Optional<ClientRegistry> client;
    private final SupportedLanguage userLanguage;
    private final String clientSessionId;
    private final String txmaAuditEncoded;

    protected UserContext(
            Session session,
            Optional<UserProfile> userProfile,
            Optional<UserCredentials> userCredentials,
            boolean userAuthenticated,
            Optional<ClientRegistry> client,
            SupportedLanguage userLanguage,
            String clientSessionId,
            String txmaAuditEncoded,
            AuthSessionItem authSession) {
        this.session = session;
        this.userProfile = userProfile;
        this.userCredentials = userCredentials;
        this.userAuthenticated = userAuthenticated;
        this.client = client;
        this.userLanguage = userLanguage;
        this.clientSessionId = clientSessionId;
        this.txmaAuditEncoded = txmaAuditEncoded;
        this.authSession = authSession;
    }

    public Session getSession() {
        return session;
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

    public String getClientName() {
        return getClient().map(ClientRegistry::getClientName).orElse("");
    }

    public SupportedLanguage getUserLanguage() {
        return userLanguage;
    }

    public String getClientSessionId() {
        return clientSessionId;
    }

    public String getTxmaAuditEncoded() {
        return txmaAuditEncoded;
    }

    public AuthSessionItem getAuthSession() {
        return authSession;
    }

    public static Builder builder(Session session) {
        return new Builder(session);
    }

    public static class Builder {
        private Session session;
        private AuthSessionItem authSession;
        private Optional<UserProfile> userProfile = Optional.empty();
        private Optional<UserCredentials> userCredentials = Optional.empty();
        private boolean userAuthenticated = false;
        private Optional<ClientRegistry> client = Optional.empty();
        private SupportedLanguage userLanguage;
        private String clientSessionId;
        private String txmaAuditEncoded;

        protected Builder(Session session) {
            this.session = session;
        }

        protected Builder(Session session, AuthSessionItem authSession) {
            this.session = session;
            this.authSession = authSession;
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

        public Builder withUserLanguage(SupportedLanguage userLanguage) {
            this.userLanguage = userLanguage;
            return this;
        }

        public Builder withClientSessionId(String clientSessionId) {
            this.clientSessionId = clientSessionId;
            return this;
        }

        public Builder withTxmaAuditEvent(String txmaAuditEncoded) {
            this.txmaAuditEncoded = txmaAuditEncoded;
            return this;
        }

        public Builder withAuthSession(AuthSessionItem authSession) {
            this.authSession = authSession;
            return this;
        }

        public UserContext build() {
            return new UserContext(
                    session,
                    userProfile,
                    userCredentials,
                    userAuthenticated,
                    client,
                    userLanguage,
                    clientSessionId,
                    txmaAuditEncoded,
                    authSession);
        }
    }
}
