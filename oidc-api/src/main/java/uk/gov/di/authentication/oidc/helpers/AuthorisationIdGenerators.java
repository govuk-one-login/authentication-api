package uk.gov.di.authentication.oidc.helpers;

import uk.gov.di.orchestration.shared.helpers.IdGenerator;

import java.util.List;

public class AuthorisationIdGenerators {
    private final AuthorisationIdGenerator sessionIdGenerator;
    private final AuthorisationIdGenerator clientSessionIdGenerator;
    private final AuthorisationIdGenerator browserSessionIdGenerator;
    private final AuthorisationIdGenerator jwtIdGenerator;

    public AuthorisationIdGenerators(
            AuthorisationIdGenerator sessionIdGenerator,
            AuthorisationIdGenerator clientSessionIdGenerator,
            AuthorisationIdGenerator browserSessionIdGenerator,
            AuthorisationIdGenerator jwtIdGenerator) {
        this.sessionIdGenerator = sessionIdGenerator;
        this.clientSessionIdGenerator = clientSessionIdGenerator;
        this.browserSessionIdGenerator = browserSessionIdGenerator;
        this.jwtIdGenerator = jwtIdGenerator;
    }

    public static AuthorisationIdGenerators withDefaults() {
        return builder().build();
    }

    public static Builder builder() {
        return new Builder();
    }

    public AuthorisationIdGenerator getSessionIdGenerator() {
        return sessionIdGenerator;
    }

    public AuthorisationIdGenerator getClientSessionIdGenerator() {
        return clientSessionIdGenerator;
    }

    public AuthorisationIdGenerator getBrowserSessionIdGenerator() {
        return browserSessionIdGenerator;
    }

    public AuthorisationIdGenerator getJwtIdGenerator() {
        return jwtIdGenerator;
    }

    public static class Builder {
        private AuthorisationIdGenerator sessionIdGenerator = IdGenerator::generate;
        private AuthorisationIdGenerator clientSessionIdGenerator = IdGenerator::generate;
        private AuthorisationIdGenerator browserSessionIdGenerator = IdGenerator::generate;
        private AuthorisationIdGenerator jwtIdGenerator = IdGenerator::generate;

        public Builder withSessionIds(String... sessionIds) {
            this.sessionIdGenerator = List.of(sessionIds).iterator()::next;
            return this;
        }

        public Builder withClientSessionIds(String... clientSessionIds) {
            this.clientSessionIdGenerator = List.of(clientSessionIds).iterator()::next;
            return this;
        }

        public Builder withBrowserSessionIds(String... bsids) {
            this.browserSessionIdGenerator = List.of(bsids).iterator()::next;
            return this;
        }

        public Builder withJwtIds(String... jwtIds) {
            this.jwtIdGenerator = List.of(jwtIds).iterator()::next;
            return this;
        }

        public AuthorisationIdGenerators build() {
            return new AuthorisationIdGenerators(
                    sessionIdGenerator,
                    clientSessionIdGenerator,
                    browserSessionIdGenerator,
                    jwtIdGenerator);
        }
    }

    public interface AuthorisationIdGenerator {
        String generate();
    }
}
