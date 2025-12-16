package uk.gov.di.orchestration.shared.lambda;

import com.amazonaws.services.lambda.runtime.Context;

public class LambdaTimer {
    private final Context context;

    public LambdaTimer(Context context) {
        this.context = context;
    }

    public long getRemainingTimeInMillis() {
        return context.getRemainingTimeInMillis();
    }

    public boolean hasTimeRemaining(long bufferMs) {
        return getRemainingTimeInMillis() > bufferMs;
    }
}
