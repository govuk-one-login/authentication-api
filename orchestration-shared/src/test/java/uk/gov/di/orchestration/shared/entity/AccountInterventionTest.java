package uk.gov.di.orchestration.shared.entity;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

// QualityGateUnitTest
class AccountInterventionTest {
    private static final AccountInterventionState CLEAR_STATE =
            new AccountInterventionState(false, false, false, false);
    private static final AccountInterventionState BLOCKED_STATE =
            new AccountInterventionState(true, false, false, false);
    private static final AccountInterventionState SUSPENDED_STATE =
            new AccountInterventionState(false, true, false, false);
    private static final AccountInterventionState SUSPENDED_RESET_PASSWORD_STATE =
            new AccountInterventionState(false, true, false, true);
    private static final AccountInterventionState SUSPENDED_REPROVE_ID_STATE =
            new AccountInterventionState(false, true, true, false);
    private static final AccountInterventionState SUSPENDED_RESET_PASSWORD_REPROVE_ID_STATE =
            new AccountInterventionState(false, true, true, true);

    // QualityGateRegressionTest
    @ParameterizedTest
    @MethodSource("standardTestCases")
    void shouldHaveCorrectStatusAfterInitialisingFromState(
            AccountInterventionState state, AccountInterventionStatus status) {
        AccountIntervention intervention = new AccountIntervention(state);
        assertThat(intervention.getStatus(), equalTo(status));
    }

    // QualityGateRegressionTest
    @ParameterizedTest
    @MethodSource("ignoreResetPasswordTestCases")
    void shouldHaveCorrectStatusWhenPasswordWasResetAfterInterventionWasApplied(
            AccountInterventionState state, AccountInterventionStatus status) {
        AccountInterventionDetails details = new AccountInterventionDetails(0L, 0L, 0L, "", 0L, 0L);
        AccountIntervention intervention = new AccountIntervention(details, state, Long.MAX_VALUE);
        assertThat(intervention.getStatus(), equalTo(status));
    }

    private static Object[][] standardTestCases() {
        return new Object[][] {
            {CLEAR_STATE, AccountInterventionStatus.NO_INTERVENTION},
            {BLOCKED_STATE, AccountInterventionStatus.BLOCKED},
            {SUSPENDED_STATE, AccountInterventionStatus.SUSPENDED_NO_ACTION},
            {SUSPENDED_RESET_PASSWORD_STATE, AccountInterventionStatus.SUSPENDED_RESET_PASSWORD},
            {SUSPENDED_REPROVE_ID_STATE, AccountInterventionStatus.SUSPENDED_REPROVE_ID},
            {
                SUSPENDED_RESET_PASSWORD_REPROVE_ID_STATE,
                AccountInterventionStatus.SUSPENDED_RESET_PASSWORD_REPROVE_ID
            },
        };
    }

    private static Object[][] ignoreResetPasswordTestCases() {
        return new Object[][] {
            {CLEAR_STATE, AccountInterventionStatus.NO_INTERVENTION},
            {BLOCKED_STATE, AccountInterventionStatus.BLOCKED},
            {SUSPENDED_STATE, AccountInterventionStatus.SUSPENDED_NO_ACTION},
            {SUSPENDED_RESET_PASSWORD_STATE, AccountInterventionStatus.NO_INTERVENTION},
            {SUSPENDED_REPROVE_ID_STATE, AccountInterventionStatus.SUSPENDED_REPROVE_ID},
            {
                SUSPENDED_RESET_PASSWORD_REPROVE_ID_STATE,
                AccountInterventionStatus.SUSPENDED_REPROVE_ID
            },
        };
    }
}
