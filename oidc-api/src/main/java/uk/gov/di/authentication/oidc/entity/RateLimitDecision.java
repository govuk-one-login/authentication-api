package uk.gov.di.authentication.oidc.entity;

public class RateLimitDecision {

    public enum RateLimitAction {
        NONE,
        RETURN_TO_RP
        // Future Rate Limit Actions
    }

    public static final RateLimitDecision NONE = new RateLimitDecision(false, RateLimitAction.NONE);
    public static final RateLimitDecision REDIRECT_TO_RP =
            new RateLimitDecision(true, RateLimitAction.RETURN_TO_RP);

    private final boolean hasExceededRateLimit;
    private final RateLimitAction action;

    public RateLimitDecision(boolean hasExceededRateLimit, RateLimitAction rateLimitAction) {

        if (!hasExceededRateLimit && !rateLimitAction.equals(RateLimitAction.NONE)) {
            throw new IllegalArgumentException(
                    "Action must be NONE if rate limit has not been exceeded");
        }

        this.hasExceededRateLimit = hasExceededRateLimit;
        this.action = rateLimitAction;
    }

    public RateLimitAction getAction() {
        return action;
    }

    public boolean hasExceededRateLimit() {
        return hasExceededRateLimit;
    }
}
