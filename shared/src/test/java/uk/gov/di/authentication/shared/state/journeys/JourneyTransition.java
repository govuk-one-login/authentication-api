package uk.gov.di.authentication.shared.state.journeys;

import uk.gov.di.authentication.shared.entity.SessionAction;
import uk.gov.di.authentication.shared.entity.SessionState;
import uk.gov.di.authentication.shared.state.UserContext;

public class JourneyTransition {

    private UserContext userContext;
    private SessionAction sessionAction;
    private SessionState expectedSessionState;

    public JourneyTransition(
            final UserContext userContext,
            final SessionAction sessionAction,
            final SessionState expectedSessionState) {
        this.userContext = userContext;
        this.sessionAction = sessionAction;
        this.expectedSessionState = expectedSessionState;
    }

    public UserContext getUserContext() {
        return userContext;
    }

    public SessionAction getSessionAction() {
        return sessionAction;
    }

    public SessionState getExpectedSessionState() {
        return expectedSessionState;
    }
}
