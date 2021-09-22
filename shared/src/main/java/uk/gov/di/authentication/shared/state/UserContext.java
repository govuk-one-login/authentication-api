package uk.gov.di.authentication.shared.state;

import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.UserProfile;

import java.util.Optional;

public class UserContext {
    private final Session session;
    private final Optional<UserProfile> userProfile;
    private final Optional<ClientRegistry> client;

    protected UserContext(
            Session session, Optional<UserProfile> userProfile, Optional<ClientRegistry> client) {
        this.session = session;
        this.userProfile = userProfile;
        this.client = client;
    }

    public Session getSession() {
        return session;
    }

    public Optional<UserProfile> getUserProfile() {
        return userProfile;
    }

    public Optional<ClientRegistry> getClient() {
        return client;
    }

    public static Builder builder(Session session) {
        return new Builder(session);
    }

    public static class Builder {
        private Session session;
        private Optional<UserProfile> userProfile = Optional.empty();
        private Optional<ClientRegistry> client = Optional.empty();

        protected Builder(Session session) {
            this.session = session;
        }

        public Builder withUserProfile(UserProfile userProfile) {
            return withUserProfile(Optional.of(userProfile));
        }

        public Builder withUserProfile(Optional<UserProfile> userProfile) {
            this.userProfile = userProfile;
            return this;
        }

        public Builder withClient(ClientRegistry client) {
            return withClient(Optional.of(client));
        }

        public Builder withClient(Optional<ClientRegistry> client) {
            this.client = client;
            return this;
        }

        public UserContext build() {
            return new UserContext(session, userProfile, client);
        }
    }
}
