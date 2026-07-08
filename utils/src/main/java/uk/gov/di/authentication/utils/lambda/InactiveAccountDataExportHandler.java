package uk.gov.di.authentication.utils.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import uk.gov.di.authentication.shared.helpers.TableNameHelper;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.utils.entity.InactiveAccountDataExportRequest;
import uk.gov.di.authentication.utils.entity.InactiveAccountDataExportResponse;

import static uk.gov.di.authentication.shared.dynamodb.DynamoClientHelper.createDynamoClient;

public class InactiveAccountDataExportHandler
        implements RequestHandler<
                InactiveAccountDataExportRequest, InactiveAccountDataExportResponse> {

    private static final Logger LOG = LogManager.getLogger(InactiveAccountDataExportHandler.class);
    private static final String USER_PROFILE_TABLE = "user-profile";

    private final DynamoDbClient client;
    private final String userProfileTableName;

    public InactiveAccountDataExportHandler(
            ConfigurationService configurationService, DynamoDbClient client) {
        this.client = client;
        this.userProfileTableName =
                TableNameHelper.getFullTableName(USER_PROFILE_TABLE, configurationService);
    }

    public InactiveAccountDataExportHandler() {
        this(
                ConfigurationService.getInstance(),
                createDynamoClient(ConfigurationService.getInstance()));
    }

    @Override
    public InactiveAccountDataExportResponse handleRequest(
            InactiveAccountDataExportRequest request, Context context) {
        if (request == null || request.parallelism() == null || request.totalSegments() == null) {
            throw new IllegalArgumentException(
                    "Request must contain 'parallelism' and 'totalSegments' fields.");
        }

        LOG.info(
                "Inactive account data export request: parallelism={}, totalSegments={}",
                request.parallelism(),
                request.totalSegments());

        return new InactiveAccountDataExportResponse(0);
    }
}
