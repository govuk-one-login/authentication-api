package uk.gov.di.orchestration.shared.services;

import com.amazonaws.services.lambda.runtime.events.ScheduledEvent;

public interface LambdaInvoker {
    public void invokeWithPayload(ScheduledEvent scheduledEvent);
}
