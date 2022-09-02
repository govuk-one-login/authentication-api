package uk.gov.di.authentication.audit.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.SNSEvent;

public abstract class BaseAuditHandler implements RequestHandler<SNSEvent, Object> {

    BaseAuditHandler() {}

    @Override
    public Object handleRequest(SNSEvent input, Context context) {
        return null;
    }
}
