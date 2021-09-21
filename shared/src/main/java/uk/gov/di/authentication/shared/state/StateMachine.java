package uk.gov.di.authentication.shared.state;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.authentication.shared.entity.SessionAction;
import uk.gov.di.authentication.shared.entity.SessionState;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import static java.util.Collections.emptyList;
import static uk.gov.di.authentication.shared.entity.SessionAction.*;
import static uk.gov.di.authentication.shared.entity.SessionState.*;
import static uk.gov.di.authentication.shared.state.conditions.TermsAndConditionsVersionNotAccepted.userHasNotAcceptedTermsAndConditionsVersion;

public class StateMachine<T, A, C> {

    private final Map<T, List<Transition<T, A, C>>> states;

    private static final Logger LOGGER = LoggerFactory.getLogger(StateMachine.class);

    public StateMachine(Map<T, List<Transition<T, A, C>>> states) {
        this.states = Collections.unmodifiableMap(states);
    }

    public T transition(T from, A action, Optional<C> context) {
        if (context.isEmpty()
                && states.getOrDefault(from, emptyList()).stream()
                                .filter(t -> t.getAction().equals(action))
                                .count()
                        > 1) {
            throw handleNoTransitionContext(from, action);
        }
        T to =
                states.getOrDefault(from, emptyList()).stream()
                        .filter(
                                t ->
                                        t.getAction().equals(action)
                                                && t.getCondition().isMet(context))
                        .findFirst()
                        .orElseThrow(() -> handleBadStateTransition(from, action))
                        .getNextState();

        LOGGER.info("Session transitioned from {} to {} on action {}", from, to, action);

        return to;
    }

    public T transition(T from, A action) {
        return transition(from, action, Optional.empty());
    }

    public static Transition.Builder<SessionState, SessionAction, UserProfile> on(
            SessionAction action) {
        return Transition.<SessionState, SessionAction, UserProfile>builder().on(action);
    }

    public static StateMachine<SessionState, SessionAction, UserProfile> userJourneyStateMachine() {
        return userJourneyStateMachine(ConfigurationService.getInstance());
    }

    public static StateMachine<SessionState, SessionAction, UserProfile> userJourneyStateMachine(
            ConfigurationService configurationService) {
        return StateMachine.<SessionState, SessionAction, UserProfile>builder()
                .when(NEW)
                .allow(on(USER_ENTERED_UNREGISTERED_EMAIL_ADDRESS).then(USER_NOT_FOUND))
                .when(RESET_PASSWORD_LINK_SENT)
                .allow(
                        on(USER_ENTERED_UNREGISTERED_EMAIL_ADDRESS).then(USER_NOT_FOUND),
                        on(SYSTEM_HAS_SENT_RESET_PASSWORD_LINK_TOO_MANY_TIMES)
                                .then(RESET_PASSWORD_LINK_MAX_RETRIES_REACHED),
                        on(SYSTEM_HAS_SENT_RESET_PASSWORD_LINK).then(RESET_PASSWORD_LINK_SENT))
                .when(RESET_PASSWORD_LINK_MAX_RETRIES_REACHED)
                .allow(
                        on(SYSTEM_HAS_SENT_RESET_PASSWORD_LINK).then(RESET_PASSWORD_LINK_SENT),
                        on(USER_ENTERED_UNREGISTERED_EMAIL_ADDRESS).then(USER_NOT_FOUND))
                .when(USER_NOT_FOUND)
                .allow(
                        on(USER_ENTERED_UNREGISTERED_EMAIL_ADDRESS).then(USER_NOT_FOUND),
                        on(USER_ENTERED_REGISTERED_EMAIL_ADDRESS).then(AUTHENTICATION_REQUIRED),
                        on(SYSTEM_HAS_SENT_EMAIL_VERIFICATION_CODE).then(VERIFY_EMAIL_CODE_SENT))
                .when(VERIFY_EMAIL_CODE_SENT)
                .allow(
                        on(USER_ENTERED_VALID_EMAIL_VERIFICATION_CODE).then(EMAIL_CODE_VERIFIED),
                        on(USER_ENTERED_INVALID_EMAIL_VERIFICATION_CODE).then(EMAIL_CODE_NOT_VALID))
                .when(EMAIL_CODE_NOT_VALID)
                .allow(
                        on(USER_ENTERED_VALID_EMAIL_VERIFICATION_CODE).then(EMAIL_CODE_VERIFIED),
                        on(USER_ENTERED_INVALID_EMAIL_VERIFICATION_CODE).then(EMAIL_CODE_NOT_VALID),
                        on(USER_ENTERED_INVALID_EMAIL_VERIFICATION_CODE_TOO_MANY_TIMES)
                                .then(EMAIL_CODE_MAX_RETRIES_REACHED))
                .when(EMAIL_CODE_MAX_RETRIES_REACHED)
                .finalState()
                .when(EMAIL_CODE_VERIFIED)
                .allow(
                        on(USER_ENTERED_INVALID_EMAIL_VERIFICATION_CODE).then(EMAIL_CODE_NOT_VALID),
                        on(USER_HAS_CREATED_A_PASSWORD).then(TWO_FACTOR_REQUIRED))
                .when(TWO_FACTOR_REQUIRED)
                .allow(on(USER_ENTERED_A_NEW_PHONE_NUMBER).then(ADDED_UNVERIFIED_PHONE_NUMBER))
                .when(ADDED_UNVERIFIED_PHONE_NUMBER)
                .allow(
                        on(SYSTEM_HAS_SENT_PHONE_VERIFICATION_CODE)
                                .then(VERIFY_PHONE_NUMBER_CODE_SENT))
                .when(VERIFY_PHONE_NUMBER_CODE_SENT)
                .allow(
                        on(USER_ENTERED_VALID_PHONE_VERIFICATION_CODE)
                                .then(PHONE_NUMBER_CODE_VERIFIED),
                        on(USER_ENTERED_INVALID_PHONE_VERIFICATION_CODE)
                                .then(PHONE_NUMBER_CODE_NOT_VALID))
                .when(PHONE_NUMBER_CODE_VERIFIED)
                .allow(on(SYSTEM_HAS_ISSUED_AUTHORIZATION_CODE).then(AUTHENTICATED))
                .when(PHONE_NUMBER_CODE_NOT_VALID)
                .allow(
                        on(USER_ENTERED_VALID_PHONE_VERIFICATION_CODE)
                                .then(PHONE_NUMBER_CODE_VERIFIED),
                        on(USER_ENTERED_INVALID_PHONE_VERIFICATION_CODE)
                                .then(PHONE_NUMBER_CODE_NOT_VALID),
                        on(USER_ENTERED_INVALID_PHONE_VERIFICATION_CODE_TOO_MANY_TIMES)
                                .then(PHONE_NUMBER_CODE_MAX_RETRIES_REACHED))
                .when(PHONE_NUMBER_CODE_MAX_RETRIES_REACHED)
                .finalState()
                .when(AUTHENTICATION_REQUIRED)
                .allow(
                        on(USER_ENTERED_VALID_CREDENTIALS).then(LOGGED_IN),
                        on(USER_ENTERED_UNREGISTERED_EMAIL_ADDRESS).then(USER_NOT_FOUND),
                        on(SYSTEM_HAS_SENT_RESET_PASSWORD_LINK).then(RESET_PASSWORD_LINK_SENT))
                .when(LOGGED_IN)
                .allow(on(SYSTEM_HAS_SENT_MFA_CODE).then(MFA_SMS_CODE_SENT))
                .when(MFA_SMS_CODE_SENT)
                .allow(
                        on(SYSTEM_HAS_SENT_MFA_CODE).then(MFA_SMS_CODE_SENT),
                        on(USER_ENTERED_VALID_MFA_CODE)
                                .then(UPDATED_TERMS_AND_CONDITIONS)
                                .ifCondition(
                                        userHasNotAcceptedTermsAndConditionsVersion(
                                                configurationService
                                                        .getTermsAndConditionsVersion())),
                        on(USER_ENTERED_VALID_MFA_CODE).then(MFA_CODE_VERIFIED).byDefault(),
                        on(USER_ENTERED_INVALID_MFA_CODE).then(MFA_CODE_NOT_VALID))
                .when(MFA_CODE_NOT_VALID)
                .allow(
                        on(USER_ENTERED_VALID_MFA_CODE)
                                .then(UPDATED_TERMS_AND_CONDITIONS)
                                .ifCondition(
                                        userHasNotAcceptedTermsAndConditionsVersion(
                                                configurationService
                                                        .getTermsAndConditionsVersion())),
                        on(USER_ENTERED_VALID_MFA_CODE).then(MFA_CODE_VERIFIED).byDefault(),
                        on(USER_ENTERED_INVALID_MFA_CODE).then(MFA_CODE_NOT_VALID),
                        on(USER_ENTERED_INVALID_MFA_CODE_TOO_MANY_TIMES)
                                .then(MFA_CODE_MAX_RETRIES_REACHED))
                .when(MFA_CODE_MAX_RETRIES_REACHED)
                .finalState()
                .when(MFA_CODE_VERIFIED)
                .allow(on(SYSTEM_HAS_ISSUED_AUTHORIZATION_CODE).then(AUTHENTICATED))
                .when(UPDATED_TERMS_AND_CONDITIONS)
                .allow(
                        on(USER_ACCEPTS_TERMS_AND_CONDITIONS)
                                .then(UPDATED_TERMS_AND_CONDITIONS_ACCEPTED),
                        on(USER_REJECTS_TERMS_AND_CONDITIONS)
                                .then(UPDATED_TERMS_AND_CONDITIONS_REJECTED))
                .when(UPDATED_TERMS_AND_CONDITIONS_ACCEPTED)
                .allow(on(SYSTEM_HAS_ISSUED_AUTHORIZATION_CODE).then(AUTHENTICATED))
                .when(UPDATED_TERMS_AND_CONDITIONS_REJECTED)
                .finalState()
                .when(AUTHENTICATED)
                .allow(on(SYSTEM_HAS_ISSUED_AUTHORIZATION_CODE).then(AUTHENTICATED))
                .build();
    }

    public static class InvalidStateTransitionException extends RuntimeException {}

    public static class NoTransitionContextProvidedException extends RuntimeException {}

    public static <T, A, C> Builder<T, A, C> builder() {
        return new Builder<>();
    }

    public static class Builder<T, A, C> {
        private final Map<T, List<Transition<T, A, C>>> states = new HashMap<>();

        public StateRuleBuilder<T, A, C> when(T state) {
            return new StateRuleBuilder<>(this, state);
        }

        protected void addStateRule(T state, List<Transition<T, A, C>> transitions) {
            this.states.put(state, transitions);
        }

        public StateMachine<T, A, C> build() {
            return new StateMachine<>(states);
        }
    }

    public static class StateRuleBuilder<T, A, C> {
        private final Builder<T, A, C> stateMachineBuilder;
        private final T state;

        @SafeVarargs
        public final Builder<T, A, C> allow(final Transition.Builder<T, A, C>... transitions) {
            stateMachineBuilder.addStateRule(
                    state,
                    Arrays.asList(transitions).stream()
                            .map(b -> b.build())
                            .collect(Collectors.toList()));
            return stateMachineBuilder;
        }

        protected StateRuleBuilder(Builder<T, A, C> stateMachineBuilder, T state) {
            this.stateMachineBuilder = stateMachineBuilder;
            this.state = state;
        }

        public Builder<T, A, C> finalState() {
            stateMachineBuilder.addStateRule(state, Collections.emptyList());
            return stateMachineBuilder;
        }
    }

    private InvalidStateTransitionException handleBadStateTransition(T from, A action) {
        LOGGER.error("Session attempted invalid transition from {} on action {}", from, action);
        return new InvalidStateTransitionException();
    }

    private NoTransitionContextProvidedException handleNoTransitionContext(T from, A action) {
        LOGGER.error(
                "More than one transition defined from {} on action {} but no context was provided",
                from,
                action);
        return new NoTransitionContextProvidedException();
    }
}
