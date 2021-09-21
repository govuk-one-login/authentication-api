package uk.gov.di.authentication.shared.state;

import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.UserProfile;

import java.util.Optional;

public class UserContext {
    private final Session session;
    private final Optional<UserProfile> userProfile;

    protected UserContext(Session session, Optional<UserProfile> userProfile) {
        this.session = session;
        this.userProfile = userProfile;
    }

    public Session getSession() {
        return session;
    }

    public Optional<UserProfile> getUserProfile() {
        return userProfile;
    }

    public static Builder builder(Session session) {
        return new Builder(session);
    }

    public static class Builder {
        private Session session;
        private Optional<UserProfile> userProfile = Optional.empty();

        protected Builder(Session session) {
            this.session = session;
        }

        public Builder withUserProfile(UserProfile userProfile) {
            this.userProfile = Optional.of(userProfile);
            return this;
        }

        public Builder withUserProfile(Optional<UserProfile> userProfile) {
            this.userProfile = userProfile;
            return this;
        }

        public UserContext build() {
            return new UserContext(session, userProfile);
        }
    }
}
