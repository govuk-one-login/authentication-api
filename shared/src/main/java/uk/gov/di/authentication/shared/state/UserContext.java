package uk.gov.di.authentication.shared.state;

import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.UserCredentials;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.helpers.LocaleHelper.SupportedLanguage;

import java.util.Optional;

public class UserContext {
    private final AuthSessionItem authSession;
    private final Optional<UserProfile> userProfile;
    private final Optional<UserCredentials> userCredentials;
    private final boolean userAuthenticated;
    private final Optional<ClientRegistry> client;
    private final SupportedLanguage userLanguage;
    private final String clientSessionId;
    private final String txmaAuditEncoded;

    protected UserContext(
            Optional<UserProfile> userProfile,
            Optional<UserCredentials> userCredentials,
            boolean userAuthenticated,
            Optional<ClientRegistry> client,
            SupportedLanguage userLanguage,
            String clientSessionId,
            String txmaAuditEncoded,
            AuthSessionItem authSession) {
        this.userProfile = userProfile;
        this.userCredentials = userCredentials;
        this.userAuthenticated = userAuthenticated;
        this.client = client;
        this.userLanguage = userLanguage;
        this.clientSessionId = clientSessionId;
        this.txmaAuditEncoded = txmaAuditEncoded;
        this.authSession = authSession;
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

    public static Builder builder(AuthSessionItem session) {
        return new Builder(session);
    }

    public static class Builder {
        private AuthSessionItem authSession;
        private Optional<UserProfile> userProfile = Optional.empty();
        private Optional<UserCredentials> userCredentials = Optional.empty();
        private boolean userAuthenticated = false;
        private Optional<ClientRegistry> client = Optional.empty();
        private SupportedLanguage userLanguage;
        private String clientSessionId;
        private String txmaAuditEncoded;

        protected Builder(AuthSessionItem authSession) {
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

        public UserContext build() {
            return new UserContext(
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
