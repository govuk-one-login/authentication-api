package uk.gov.di.authentication.audit.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.SQSEvent;

public class StorageSQSAuditHandler implements RequestHandler<SQSEvent, Object> {

    public StorageSQSAuditHandler() {}

    @Override
    public Object handleRequest(SQSEvent input, Context context) {
        return null;
    }
}
