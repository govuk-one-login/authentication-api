package uk.gov.di.authentication.shared.state;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.authentication.shared.entity.SessionAction;
import uk.gov.di.authentication.shared.entity.SessionState;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import static java.util.Collections.emptyList;
import static uk.gov.di.authentication.shared.entity.SessionAction.ACCOUNT_LOCK_EXPIRED;
import static uk.gov.di.authentication.shared.entity.SessionAction.SYSTEM_HAS_ISSUED_AUTHORIZATION_CODE;
import static uk.gov.di.authentication.shared.entity.SessionAction.SYSTEM_HAS_SENT_EMAIL_VERIFICATION_CODE;
import static uk.gov.di.authentication.shared.entity.SessionAction.SYSTEM_HAS_SENT_MFA_CODE;
import static uk.gov.di.authentication.shared.entity.SessionAction.SYSTEM_HAS_SENT_PHONE_VERIFICATION_CODE;
import static uk.gov.di.authentication.shared.entity.SessionAction.SYSTEM_HAS_SENT_RESET_PASSWORD_LINK;
import static uk.gov.di.authentication.shared.entity.SessionAction.SYSTEM_HAS_SENT_RESET_PASSWORD_LINK_TOO_MANY_TIMES;
import static uk.gov.di.authentication.shared.entity.SessionAction.SYSTEM_HAS_SENT_TOO_MANY_EMAIL_VERIFICATION_CODES;
import static uk.gov.di.authentication.shared.entity.SessionAction.SYSTEM_HAS_SENT_TOO_MANY_MFA_CODES;
import static uk.gov.di.authentication.shared.entity.SessionAction.SYSTEM_HAS_SENT_TOO_MANY_PHONE_VERIFICATION_CODES;
import static uk.gov.di.authentication.shared.entity.SessionAction.SYSTEM_IS_BLOCKED_FROM_SENDING_ANY_EMAIL_VERIFICATION_CODES;
import static uk.gov.di.authentication.shared.entity.SessionAction.SYSTEM_IS_BLOCKED_FROM_SENDING_ANY_MFA_VERIFICATION_CODES;
import static uk.gov.di.authentication.shared.entity.SessionAction.SYSTEM_IS_BLOCKED_FROM_SENDING_ANY_PHONE_VERIFICATION_CODES;
import static uk.gov.di.authentication.shared.entity.SessionAction.USER_ACCEPTS_TERMS_AND_CONDITIONS;
import static uk.gov.di.authentication.shared.entity.SessionAction.USER_ENTERED_A_NEW_PHONE_NUMBER;
import static uk.gov.di.authentication.shared.entity.SessionAction.USER_ENTERED_INVALID_EMAIL_VERIFICATION_CODE;
import static uk.gov.di.authentication.shared.entity.SessionAction.USER_ENTERED_INVALID_EMAIL_VERIFICATION_CODE_TOO_MANY_TIMES;
import static uk.gov.di.authentication.shared.entity.SessionAction.USER_ENTERED_INVALID_MFA_CODE;
import static uk.gov.di.authentication.shared.entity.SessionAction.USER_ENTERED_INVALID_MFA_CODE_TOO_MANY_TIMES;
import static uk.gov.di.authentication.shared.entity.SessionAction.USER_ENTERED_INVALID_PASSWORD_TOO_MANY_TIMES;
import static uk.gov.di.authentication.shared.entity.SessionAction.USER_ENTERED_INVALID_PHONE_VERIFICATION_CODE;
import static uk.gov.di.authentication.shared.entity.SessionAction.USER_ENTERED_INVALID_PHONE_VERIFICATION_CODE_TOO_MANY_TIMES;
import static uk.gov.di.authentication.shared.entity.SessionAction.USER_ENTERED_REGISTERED_EMAIL_ADDRESS;
import static uk.gov.di.authentication.shared.entity.SessionAction.USER_ENTERED_UNREGISTERED_EMAIL_ADDRESS;
import static uk.gov.di.authentication.shared.entity.SessionAction.USER_ENTERED_VALID_CREDENTIALS;
import static uk.gov.di.authentication.shared.entity.SessionAction.USER_ENTERED_VALID_EMAIL_VERIFICATION_CODE;
import static uk.gov.di.authentication.shared.entity.SessionAction.USER_ENTERED_VALID_MFA_CODE;
import static uk.gov.di.authentication.shared.entity.SessionAction.USER_ENTERED_VALID_PHONE_VERIFICATION_CODE;
import static uk.gov.di.authentication.shared.entity.SessionAction.USER_HAS_ACTIONED_CONSENT;
import static uk.gov.di.authentication.shared.entity.SessionAction.USER_HAS_CREATED_A_PASSWORD;
import static uk.gov.di.authentication.shared.entity.SessionAction.USER_HAS_STARTED_A_NEW_JOURNEY;
import static uk.gov.di.authentication.shared.entity.SessionAction.USER_HAS_STARTED_A_NEW_JOURNEY_WITH_LOGIN_REQUIRED;
import static uk.gov.di.authentication.shared.entity.SessionState.ACCOUNT_TEMPORARILY_LOCKED;
import static uk.gov.di.authentication.shared.entity.SessionState.ADDED_UNVERIFIED_PHONE_NUMBER;
import static uk.gov.di.authentication.shared.entity.SessionState.AUTHENTICATED;
import static uk.gov.di.authentication.shared.entity.SessionState.AUTHENTICATION_REQUIRED;
import static uk.gov.di.authentication.shared.entity.SessionState.CONSENT_ADDED;
import static uk.gov.di.authentication.shared.entity.SessionState.CONSENT_REQUIRED;
import static uk.gov.di.authentication.shared.entity.SessionState.EMAIL_CODE_MAX_RETRIES_REACHED;
import static uk.gov.di.authentication.shared.entity.SessionState.EMAIL_CODE_NOT_VALID;
import static uk.gov.di.authentication.shared.entity.SessionState.EMAIL_CODE_REQUESTS_BLOCKED;
import static uk.gov.di.authentication.shared.entity.SessionState.EMAIL_CODE_VERIFIED;
import static uk.gov.di.authentication.shared.entity.SessionState.EMAIL_MAX_CODES_SENT;
import static uk.gov.di.authentication.shared.entity.SessionState.LOGGED_IN;
import static uk.gov.di.authentication.shared.entity.SessionState.MFA_CODE_MAX_RETRIES_REACHED;
import static uk.gov.di.authentication.shared.entity.SessionState.MFA_CODE_NOT_VALID;
import static uk.gov.di.authentication.shared.entity.SessionState.MFA_CODE_REQUESTS_BLOCKED;
import static uk.gov.di.authentication.shared.entity.SessionState.MFA_CODE_VERIFIED;
import static uk.gov.di.authentication.shared.entity.SessionState.MFA_SMS_CODE_SENT;
import static uk.gov.di.authentication.shared.entity.SessionState.MFA_SMS_MAX_CODES_SENT;
import static uk.gov.di.authentication.shared.entity.SessionState.NEW;
import static uk.gov.di.authentication.shared.entity.SessionState.PHONE_NUMBER_CODE_MAX_RETRIES_REACHED;
import static uk.gov.di.authentication.shared.entity.SessionState.PHONE_NUMBER_CODE_NOT_VALID;
import static uk.gov.di.authentication.shared.entity.SessionState.PHONE_NUMBER_CODE_REQUESTS_BLOCKED;
import static uk.gov.di.authentication.shared.entity.SessionState.PHONE_NUMBER_CODE_VERIFIED;
import static uk.gov.di.authentication.shared.entity.SessionState.PHONE_NUMBER_MAX_CODES_SENT;
import static uk.gov.di.authentication.shared.entity.SessionState.RESET_PASSWORD_LINK_MAX_RETRIES_REACHED;
import static uk.gov.di.authentication.shared.entity.SessionState.RESET_PASSWORD_LINK_SENT;
import static uk.gov.di.authentication.shared.entity.SessionState.TWO_FACTOR_REQUIRED;
import static uk.gov.di.authentication.shared.entity.SessionState.UPDATED_TERMS_AND_CONDITIONS;
import static uk.gov.di.authentication.shared.entity.SessionState.UPDATED_TERMS_AND_CONDITIONS_ACCEPTED;
import static uk.gov.di.authentication.shared.entity.SessionState.UPLIFT_REQUIRED_CM;
import static uk.gov.di.authentication.shared.entity.SessionState.USER_NOT_FOUND;
import static uk.gov.di.authentication.shared.entity.SessionState.VERIFY_EMAIL_CODE_SENT;
import static uk.gov.di.authentication.shared.entity.SessionState.VERIFY_PHONE_NUMBER_CODE_SENT;
import static uk.gov.di.authentication.shared.state.conditions.AggregateCondition.and;
import static uk.gov.di.authentication.shared.state.conditions.ClientDoesNotRequireMfa.clientDoesNotRequireMfa;
import static uk.gov.di.authentication.shared.state.conditions.ConsentNotGiven.userHasNotGivenConsent;
import static uk.gov.di.authentication.shared.state.conditions.CredentialTrustUpliftRequired.upliftRequired;
import static uk.gov.di.authentication.shared.state.conditions.PhoneNumberUnverified.phoneNumberUnverified;
import static uk.gov.di.authentication.shared.state.conditions.RequestedLevelOfTrustEquals.requestedLevelOfTrustIsCm;
import static uk.gov.di.authentication.shared.state.conditions.TermsAndConditionsVersionNotAccepted.userHasNotAcceptedTermsAndConditionsVersion;

public class StateMachine<T, A, C> {

    private final Map<T, List<Transition<T, A, C>>> states;

    private static final Logger LOGGER = LoggerFactory.getLogger(StateMachine.class);

    public StateMachine(Map<T, List<Transition<T, A, C>>> states) {
        this.states = Collections.unmodifiableMap(states);
    }

    private T transition(T from, A action, Optional<C> context) {
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

    public T transition(T from, A action, C context) {
        return transition(from, action, Optional.of(context));
    }

    public T transition(T from, A action) {
        return transition(from, action, Optional.empty());
    }

    public static Transition.Builder<SessionState, SessionAction, UserContext> on(
            SessionAction action) {
        return Transition.<SessionState, SessionAction, UserContext>builder().on(action);
    }

    public static StateMachine<SessionState, SessionAction, UserContext> userJourneyStateMachine() {
        return userJourneyStateMachine(ConfigurationService.getInstance());
    }

    public static StateMachine<SessionState, SessionAction, UserContext> userJourneyStateMachine(
            ConfigurationService configurationService) {
        return StateMachine.<SessionState, SessionAction, UserContext>builder()
                .when(NEW)
                .allow(
                        on(USER_ENTERED_REGISTERED_EMAIL_ADDRESS).then(AUTHENTICATION_REQUIRED),
                        on(USER_ENTERED_UNREGISTERED_EMAIL_ADDRESS).then(USER_NOT_FOUND),
                        on(SYSTEM_HAS_SENT_EMAIL_VERIFICATION_CODE).then(VERIFY_EMAIL_CODE_SENT),
                        on(USER_HAS_STARTED_A_NEW_JOURNEY).then(NEW),
                        on(USER_HAS_STARTED_A_NEW_JOURNEY_WITH_LOGIN_REQUIRED).then(NEW))
                .when(RESET_PASSWORD_LINK_SENT)
                .allow(
                        on(USER_ENTERED_UNREGISTERED_EMAIL_ADDRESS).then(USER_NOT_FOUND),
                        on(SYSTEM_HAS_SENT_RESET_PASSWORD_LINK_TOO_MANY_TIMES)
                                .then(RESET_PASSWORD_LINK_MAX_RETRIES_REACHED),
                        on(SYSTEM_HAS_SENT_RESET_PASSWORD_LINK).then(RESET_PASSWORD_LINK_SENT))
                .when(RESET_PASSWORD_LINK_MAX_RETRIES_REACHED)
                .allow(
                        on(SYSTEM_HAS_SENT_RESET_PASSWORD_LINK).then(RESET_PASSWORD_LINK_SENT),
                        on(USER_ENTERED_UNREGISTERED_EMAIL_ADDRESS).then(USER_NOT_FOUND),
                        on(USER_HAS_STARTED_A_NEW_JOURNEY).then(NEW),
                        on(USER_HAS_STARTED_A_NEW_JOURNEY_WITH_LOGIN_REQUIRED).then(NEW))
                .when(USER_NOT_FOUND)
                .allow(
                        on(USER_ENTERED_UNREGISTERED_EMAIL_ADDRESS).then(USER_NOT_FOUND),
                        on(USER_ENTERED_REGISTERED_EMAIL_ADDRESS).then(AUTHENTICATION_REQUIRED),
                        on(SYSTEM_HAS_SENT_EMAIL_VERIFICATION_CODE).then(VERIFY_EMAIL_CODE_SENT),
                        on(USER_HAS_STARTED_A_NEW_JOURNEY).then(NEW),
                        on(USER_HAS_STARTED_A_NEW_JOURNEY_WITH_LOGIN_REQUIRED).then(NEW))
                .when(VERIFY_EMAIL_CODE_SENT)
                .allow(
                        on(USER_ENTERED_REGISTERED_EMAIL_ADDRESS).then(AUTHENTICATION_REQUIRED),
                        on(USER_ENTERED_UNREGISTERED_EMAIL_ADDRESS).then(NEW),
                        on(USER_ENTERED_VALID_EMAIL_VERIFICATION_CODE).then(EMAIL_CODE_VERIFIED),
                        on(SYSTEM_HAS_SENT_TOO_MANY_EMAIL_VERIFICATION_CODES)
                                .then(EMAIL_MAX_CODES_SENT),
                        on(USER_ENTERED_INVALID_EMAIL_VERIFICATION_CODE).then(EMAIL_CODE_NOT_VALID),
                        on(USER_HAS_STARTED_A_NEW_JOURNEY).then(NEW),
                        on(USER_HAS_STARTED_A_NEW_JOURNEY_WITH_LOGIN_REQUIRED).then(NEW))
                .when(EMAIL_MAX_CODES_SENT)
                .allow(
                        on(SYSTEM_HAS_SENT_EMAIL_VERIFICATION_CODE).then(VERIFY_EMAIL_CODE_SENT),
                        on(SYSTEM_IS_BLOCKED_FROM_SENDING_ANY_EMAIL_VERIFICATION_CODES)
                                .then(EMAIL_CODE_REQUESTS_BLOCKED),
                        on(USER_HAS_STARTED_A_NEW_JOURNEY).then(NEW),
                        on(USER_HAS_STARTED_A_NEW_JOURNEY_WITH_LOGIN_REQUIRED).then(NEW))
                .when(EMAIL_CODE_REQUESTS_BLOCKED)
                .allow(on(SYSTEM_HAS_SENT_EMAIL_VERIFICATION_CODE).then(VERIFY_EMAIL_CODE_SENT))
                .when(EMAIL_CODE_NOT_VALID)
                .allow(
                        on(USER_ENTERED_VALID_EMAIL_VERIFICATION_CODE).then(EMAIL_CODE_VERIFIED),
                        on(USER_ENTERED_INVALID_EMAIL_VERIFICATION_CODE).then(EMAIL_CODE_NOT_VALID),
                        on(USER_ENTERED_INVALID_EMAIL_VERIFICATION_CODE_TOO_MANY_TIMES)
                                .then(EMAIL_CODE_MAX_RETRIES_REACHED),
                        on(USER_HAS_STARTED_A_NEW_JOURNEY).then(NEW),
                        on(USER_HAS_STARTED_A_NEW_JOURNEY_WITH_LOGIN_REQUIRED).then(NEW))
                .when(EMAIL_CODE_MAX_RETRIES_REACHED)
                .finalState()
                .when(EMAIL_CODE_VERIFIED)
                .allow(
                        on(USER_ENTERED_INVALID_EMAIL_VERIFICATION_CODE).then(EMAIL_CODE_NOT_VALID),
                        on(USER_HAS_CREATED_A_PASSWORD).then(TWO_FACTOR_REQUIRED),
                        on(USER_HAS_STARTED_A_NEW_JOURNEY).then(NEW),
                        on(USER_HAS_STARTED_A_NEW_JOURNEY_WITH_LOGIN_REQUIRED).then(NEW))
                .when(TWO_FACTOR_REQUIRED)
                .allow(
                        on(USER_ENTERED_A_NEW_PHONE_NUMBER).then(ADDED_UNVERIFIED_PHONE_NUMBER),
                        on(USER_HAS_STARTED_A_NEW_JOURNEY).then(NEW),
                        on(USER_HAS_STARTED_A_NEW_JOURNEY_WITH_LOGIN_REQUIRED).then(NEW))
                .when(ADDED_UNVERIFIED_PHONE_NUMBER)
                .allow(
                        on(SYSTEM_HAS_SENT_PHONE_VERIFICATION_CODE)
                                .then(VERIFY_PHONE_NUMBER_CODE_SENT),
                        on(USER_HAS_STARTED_A_NEW_JOURNEY).then(NEW),
                        on(USER_HAS_STARTED_A_NEW_JOURNEY_WITH_LOGIN_REQUIRED).then(NEW))
                .when(VERIFY_PHONE_NUMBER_CODE_SENT)
                .allow(
                        on(USER_ENTERED_VALID_PHONE_VERIFICATION_CODE)
                                .then(CONSENT_REQUIRED)
                                .ifCondition(userHasNotGivenConsent()),
                        on(USER_ENTERED_VALID_PHONE_VERIFICATION_CODE)
                                .then(PHONE_NUMBER_CODE_VERIFIED),
                        on(SYSTEM_HAS_SENT_TOO_MANY_PHONE_VERIFICATION_CODES)
                                .then(PHONE_NUMBER_MAX_CODES_SENT),
                        on(USER_ENTERED_INVALID_PHONE_VERIFICATION_CODE)
                                .then(PHONE_NUMBER_CODE_NOT_VALID),
                        on(USER_HAS_STARTED_A_NEW_JOURNEY).then(NEW),
                        on(USER_HAS_STARTED_A_NEW_JOURNEY_WITH_LOGIN_REQUIRED).then(NEW))
                .when(PHONE_NUMBER_MAX_CODES_SENT)
                .allow(
                        on(SYSTEM_HAS_SENT_PHONE_VERIFICATION_CODE)
                                .then(VERIFY_PHONE_NUMBER_CODE_SENT),
                        on(SYSTEM_IS_BLOCKED_FROM_SENDING_ANY_PHONE_VERIFICATION_CODES)
                                .then(PHONE_NUMBER_CODE_REQUESTS_BLOCKED),
                        on(USER_HAS_STARTED_A_NEW_JOURNEY).then(NEW),
                        on(USER_HAS_STARTED_A_NEW_JOURNEY_WITH_LOGIN_REQUIRED).then(NEW))
                .when(PHONE_NUMBER_CODE_REQUESTS_BLOCKED)
                .allow(
                        on(SYSTEM_HAS_SENT_PHONE_VERIFICATION_CODE)
                                .then(VERIFY_PHONE_NUMBER_CODE_SENT))
                .when(PHONE_NUMBER_CODE_VERIFIED)
                .allow(
                        on(SYSTEM_HAS_ISSUED_AUTHORIZATION_CODE).then(AUTHENTICATED),
                        on(USER_HAS_STARTED_A_NEW_JOURNEY).then(NEW),
                        on(USER_HAS_STARTED_A_NEW_JOURNEY_WITH_LOGIN_REQUIRED).then(NEW))
                .when(PHONE_NUMBER_CODE_NOT_VALID)
                .allow(
                        on(USER_ENTERED_VALID_PHONE_VERIFICATION_CODE)
                                .then(PHONE_NUMBER_CODE_VERIFIED),
                        on(USER_ENTERED_INVALID_PHONE_VERIFICATION_CODE)
                                .then(PHONE_NUMBER_CODE_NOT_VALID),
                        on(USER_ENTERED_INVALID_PHONE_VERIFICATION_CODE_TOO_MANY_TIMES)
                                .then(PHONE_NUMBER_CODE_MAX_RETRIES_REACHED),
                        on(USER_HAS_STARTED_A_NEW_JOURNEY).then(NEW),
                        on(USER_HAS_STARTED_A_NEW_JOURNEY_WITH_LOGIN_REQUIRED).then(NEW))
                .when(PHONE_NUMBER_CODE_MAX_RETRIES_REACHED)
                .finalState()
                .when(ACCOUNT_TEMPORARILY_LOCKED)
                .allow(on(SYSTEM_HAS_SENT_RESET_PASSWORD_LINK).then(RESET_PASSWORD_LINK_SENT))
                .when(AUTHENTICATION_REQUIRED)
                .allow(
                        on(USER_ENTERED_VALID_CREDENTIALS)
                                .ifCondition(phoneNumberUnverified())
                                .then(TWO_FACTOR_REQUIRED),
                        on(USER_ENTERED_VALID_CREDENTIALS)
                                .ifCondition(
                                        and(
                                                clientDoesNotRequireMfa(),
                                                userHasNotAcceptedTermsAndConditionsVersion(
                                                        configurationService
                                                                .getTermsAndConditionsVersion())))
                                .then(UPDATED_TERMS_AND_CONDITIONS),
                        on(USER_ENTERED_VALID_CREDENTIALS)
                                .ifCondition(
                                        and(clientDoesNotRequireMfa(), userHasNotGivenConsent()))
                                .then(CONSENT_REQUIRED),
                        on(USER_ENTERED_VALID_CREDENTIALS)
                                .ifCondition(clientDoesNotRequireMfa())
                                .then(AUTHENTICATED),
                        on(USER_ENTERED_VALID_CREDENTIALS).then(LOGGED_IN),
                        on(USER_ENTERED_UNREGISTERED_EMAIL_ADDRESS).then(USER_NOT_FOUND),
                        on(SYSTEM_HAS_SENT_RESET_PASSWORD_LINK).then(RESET_PASSWORD_LINK_SENT),
                        on(USER_ENTERED_INVALID_PASSWORD_TOO_MANY_TIMES)
                                .then(ACCOUNT_TEMPORARILY_LOCKED),
                        on(ACCOUNT_LOCK_EXPIRED).then(AUTHENTICATION_REQUIRED),
                        on(USER_HAS_STARTED_A_NEW_JOURNEY).then(NEW),
                        on(USER_HAS_STARTED_A_NEW_JOURNEY_WITH_LOGIN_REQUIRED).then(NEW))
                .when(LOGGED_IN)
                .allow(
                        on(SYSTEM_HAS_SENT_MFA_CODE).then(MFA_SMS_CODE_SENT),
                        on(USER_HAS_STARTED_A_NEW_JOURNEY).then(NEW),
                        on(USER_HAS_STARTED_A_NEW_JOURNEY_WITH_LOGIN_REQUIRED).then(NEW))
                .when(MFA_SMS_CODE_SENT)
                .allow(
                        on(SYSTEM_HAS_SENT_MFA_CODE).then(MFA_SMS_CODE_SENT),
                        on(SYSTEM_HAS_SENT_TOO_MANY_MFA_CODES).then(MFA_SMS_MAX_CODES_SENT),
                        on(USER_ENTERED_VALID_MFA_CODE)
                                .then(UPDATED_TERMS_AND_CONDITIONS)
                                .ifCondition(
                                        userHasNotAcceptedTermsAndConditionsVersion(
                                                configurationService
                                                        .getTermsAndConditionsVersion())),
                        on(USER_ENTERED_VALID_MFA_CODE).then(MFA_CODE_VERIFIED).byDefault(),
                        on(USER_ENTERED_INVALID_MFA_CODE).then(MFA_CODE_NOT_VALID),
                        on(USER_HAS_STARTED_A_NEW_JOURNEY).then(NEW),
                        on(USER_HAS_STARTED_A_NEW_JOURNEY_WITH_LOGIN_REQUIRED).then(NEW))
                .when(MFA_SMS_MAX_CODES_SENT)
                .allow(
                        on(SYSTEM_HAS_SENT_MFA_CODE).then(MFA_SMS_CODE_SENT),
                        on(SYSTEM_IS_BLOCKED_FROM_SENDING_ANY_MFA_VERIFICATION_CODES)
                                .then(MFA_CODE_REQUESTS_BLOCKED),
                        on(USER_HAS_STARTED_A_NEW_JOURNEY).then(NEW),
                        on(USER_HAS_STARTED_A_NEW_JOURNEY_WITH_LOGIN_REQUIRED).then(NEW))
                .when(MFA_CODE_REQUESTS_BLOCKED)
                .allow(on(SYSTEM_HAS_SENT_MFA_CODE).then(MFA_SMS_CODE_SENT))
                .when(MFA_CODE_NOT_VALID)
                .allow(
                        on(USER_ENTERED_VALID_MFA_CODE)
                                .then(UPDATED_TERMS_AND_CONDITIONS)
                                .ifCondition(
                                        userHasNotAcceptedTermsAndConditionsVersion(
                                                configurationService
                                                        .getTermsAndConditionsVersion())),
                        on(USER_ENTERED_VALID_MFA_CODE)
                                .then(CONSENT_REQUIRED)
                                .ifCondition(userHasNotGivenConsent()),
                        on(USER_ENTERED_VALID_MFA_CODE).then(MFA_CODE_VERIFIED).byDefault(),
                        on(USER_ENTERED_INVALID_MFA_CODE).then(MFA_CODE_NOT_VALID),
                        on(USER_ENTERED_INVALID_MFA_CODE_TOO_MANY_TIMES)
                                .then(MFA_CODE_MAX_RETRIES_REACHED),
                        on(USER_HAS_STARTED_A_NEW_JOURNEY).then(NEW),
                        on(USER_HAS_STARTED_A_NEW_JOURNEY_WITH_LOGIN_REQUIRED).then(NEW))
                .when(MFA_CODE_MAX_RETRIES_REACHED)
                .finalState()
                .when(MFA_CODE_VERIFIED)
                .allow(on(SYSTEM_HAS_ISSUED_AUTHORIZATION_CODE).then(AUTHENTICATED))
                .when(UPDATED_TERMS_AND_CONDITIONS)
                .allow(
                        on(USER_ACCEPTS_TERMS_AND_CONDITIONS)
                                .then(CONSENT_REQUIRED)
                                .ifCondition(userHasNotGivenConsent()),
                        on(USER_ACCEPTS_TERMS_AND_CONDITIONS)
                                .then(UPDATED_TERMS_AND_CONDITIONS_ACCEPTED),
                        on(USER_HAS_STARTED_A_NEW_JOURNEY).then(NEW),
                        on(USER_HAS_STARTED_A_NEW_JOURNEY_WITH_LOGIN_REQUIRED).then(NEW))
                .when(UPDATED_TERMS_AND_CONDITIONS_ACCEPTED)
                .allow(
                        on(SYSTEM_HAS_ISSUED_AUTHORIZATION_CODE).then(AUTHENTICATED),
                        on(USER_HAS_STARTED_A_NEW_JOURNEY).then(NEW),
                        on(USER_HAS_STARTED_A_NEW_JOURNEY_WITH_LOGIN_REQUIRED).then(NEW))
                .when(CONSENT_REQUIRED)
                .allow(
                        on(USER_HAS_ACTIONED_CONSENT).then(CONSENT_ADDED),
                        on(USER_HAS_STARTED_A_NEW_JOURNEY).then(NEW),
                        on(USER_HAS_STARTED_A_NEW_JOURNEY_WITH_LOGIN_REQUIRED).then(NEW))
                .when(CONSENT_ADDED)
                .allow(
                        on(SYSTEM_HAS_ISSUED_AUTHORIZATION_CODE).then(AUTHENTICATED),
                        on(USER_HAS_STARTED_A_NEW_JOURNEY).then(NEW),
                        on(USER_HAS_STARTED_A_NEW_JOURNEY_WITH_LOGIN_REQUIRED).then(NEW))
                .when(AUTHENTICATED)
                .allow(
                        on(SYSTEM_HAS_ISSUED_AUTHORIZATION_CODE).then(AUTHENTICATED),
                        on(USER_HAS_STARTED_A_NEW_JOURNEY)
                                .ifCondition(and(upliftRequired(), requestedLevelOfTrustIsCm()))
                                .then(UPLIFT_REQUIRED_CM),
                        on(USER_HAS_STARTED_A_NEW_JOURNEY).then(AUTHENTICATED),
                        on(USER_HAS_STARTED_A_NEW_JOURNEY_WITH_LOGIN_REQUIRED)
                                .then(AUTHENTICATION_REQUIRED))
                .when(UPLIFT_REQUIRED_CM)
                .allow(on(SYSTEM_HAS_SENT_MFA_CODE).then(MFA_SMS_CODE_SENT))
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
