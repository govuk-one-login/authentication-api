package uk.gov.di.authentication.utils.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.DynamodbEvent;
import com.amazonaws.services.lambda.runtime.events.DynamodbEvent.DynamodbStreamRecord;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ExperianPhoneCheckHandler implements RequestHandler<DynamodbEvent, Void> {

    private static final Logger LOG = LogManager.getLogger(ExperianPhoneCheckHandler.class);

    @Override
    public Void handleRequest(DynamodbEvent dynamodbEvent, Context context) {

        int recordLength = 0;

        for (DynamodbStreamRecord record : dynamodbEvent.getRecords()) {

            if (record == null) {
                continue;
            }
            recordLength++;
        }

        LOG.info(
                "Skeleton Experian phone check lambda has been triggered for {} individual streaming records",
                recordLength);

        return null;
    }
}
