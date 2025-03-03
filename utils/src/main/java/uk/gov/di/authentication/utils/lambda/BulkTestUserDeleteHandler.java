package uk.gov.di.authentication.utils.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoAuthenticationService;

import java.util.ArrayList;
import java.util.List;

public class BulkTestUserDeleteHandler implements RequestHandler<String, Void> {
    private static final Logger LOG = LogManager.getLogger(BulkTestUserDeleteHandler.class);
    private final DynamoAuthenticationService dynamoAuthenticationService;

    public BulkTestUserDeleteHandler(ConfigurationService configurationService) {
        this.dynamoAuthenticationService = new DynamoAuthenticationService(configurationService);
    }

    public BulkTestUserDeleteHandler() {
        this(ConfigurationService.getInstance());
    }

    @Override
    public Void handleRequest(String input, Context context) {
        LOG.info("Commencing deletion of all test users");

        long startTime = System.nanoTime();
        List<UserProfile> allTestUsers = dynamoAuthenticationService.getAllBulkTestUsers();
        long endTime = System.nanoTime();
        long durationInMilliseconds = (endTime - startTime) / 1000000;
        LOG.info("{} records found in {} ms", allTestUsers.size(), durationInMilliseconds);

        List<String> batch = new ArrayList<>();

        while (!allTestUsers.isEmpty()) {

            String testUserEmailAddress = allTestUsers.remove(0).getEmail();
            batch.add(testUserEmailAddress);

            if (batch.size() % 100 == 0) {
                deleteTestUserBatch(batch);
                batch = new ArrayList<>();
            }
        }

        deleteTestUserBatch(batch);
        return null;
    }

    private void deleteTestUserBatch(List<String> batch) {
        try {
            dynamoAuthenticationService.deleteBatchTestUsers(batch);
        } catch (Exception e) {
            LOG.error("User Profile or Credentials Dynamo Table exception thrown", e);
        }
    }
}
