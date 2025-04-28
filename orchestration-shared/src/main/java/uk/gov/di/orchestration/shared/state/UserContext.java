package uk.gov.di.orchestration.shared.state;

import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.entity.OrchClientSessionItem;
import uk.gov.di.orchestration.shared.entity.OrchSessionItem;
import uk.gov.di.orchestration.shared.entity.Session;
import uk.gov.di.orchestration.shared.entity.UserCredentials;
import uk.gov.di.orchestration.shared.entity.UserProfile;
import uk.gov.di.orchestration.shared.helpers.LocaleHelper.SupportedLanguage;

import java.util.Optional;

public class UserContext {
    private final Session session;
    private final String sessionId;
    private final Optional<UserProfile> userProfile;
    private final Optional<UserInfo> authUserInfo;
    private final Optional<UserCredentials> userCredentials;
    private final boolean userAuthenticated;
    private final Optional<ClientRegistry> client;
    private final OrchClientSessionItem orchClientSession;
    private final SupportedLanguage userLanguage;
    private final String clientSessionId;
    private final OrchSessionItem orchSession;

    protected UserContext(
            Session session,
            String sessionId,
            Optional<UserProfile> userProfile,
            Optional<UserInfo> authUserInfo,
            Optional<UserCredentials> userCredentials,
            boolean userAuthenticated,
            Optional<ClientRegistry> client,
            OrchClientSessionItem orchClientSession,
            SupportedLanguage userLanguage,
            String clientSessionId,
            OrchSessionItem orchSession) {
        this.session = session;
        this.sessionId = sessionId;
        this.userProfile = userProfile;
        this.authUserInfo = authUserInfo;
        this.userCredentials = userCredentials;
        this.userAuthenticated = userAuthenticated;
        this.client = client;
        this.orchClientSession = orchClientSession;
        this.userLanguage = userLanguage;
        this.clientSessionId = clientSessionId;
        this.orchSession = orchSession;
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

    public Optional<UserInfo> getAuthUserInfo() {
        return authUserInfo;
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

    public static Builder builder(Session session) {
        return new Builder(session);
    }

    public static class Builder {
        private final Session session;
        private String sessionId;
        private Optional<UserProfile> userProfile = Optional.empty();
        private Optional<UserInfo> authUserInfo = Optional.empty();
        private Optional<UserCredentials> userCredentials = Optional.empty();
        private boolean userAuthenticated = false;
        private Optional<ClientRegistry> client = Optional.empty();
        private OrchClientSessionItem orchClientSession;
        private SupportedLanguage userLanguage;
        private String clientSessionId;
        private OrchSessionItem orchSession;

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

        public Builder withAuthUserInfo(Optional<UserInfo> authUserInfo) {
            this.authUserInfo = authUserInfo;
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
                    session,
                    sessionId,
                    userProfile,
                    authUserInfo,
                    userCredentials,
                    userAuthenticated,
                    client,
                    orchClientSession,
                    userLanguage,
                    clientSessionId,
                    orchSession);
        }
    }
}
