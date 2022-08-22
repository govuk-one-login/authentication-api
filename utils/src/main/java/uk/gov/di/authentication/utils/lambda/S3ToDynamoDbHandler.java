package uk.gov.di.authentication.utils.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.S3Event;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import uk.gov.di.authentication.shared.services.CommonPasswordsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

public class S3ToDynamoDbHandler implements RequestHandler<S3Event, Void> {
    private static final Logger LOG = LogManager.getLogger(S3ToDynamoDbHandler.class);
    private final CommonPasswordsService commonPasswordsService;
    private final S3Client client;

    public S3ToDynamoDbHandler(CommonPasswordsService commonPasswordsService, S3Client client) {
        this.commonPasswordsService = commonPasswordsService;
        this.client = client;
    }

    public S3ToDynamoDbHandler(ConfigurationService configurationService, S3Client client) {
        this.commonPasswordsService = new CommonPasswordsService(configurationService);
        this.client = client;
    }

    public S3ToDynamoDbHandler() {
        this(
                ConfigurationService.getInstance(),
                S3Client.builder().region((Region.EU_WEST_2)).build());
    }

    @Override
    public Void handleRequest(S3Event input, Context context) {

        var bucket = input.getRecords().get(0).getS3().getBucket().getName();
        var fileKey = input.getRecords().get(0).getS3().getObject().getKey();

        LOG.info("Using bucket:{} and fileKey:{}", bucket, fileKey);
        var getObjectRequest = GetObjectRequest.builder().bucket(bucket).key(fileKey).build();
        var fileContent = client.getObject(getObjectRequest);

        List<String> batch = new ArrayList<>();
        String line;

        try (var bufferedReader = new BufferedReader(new InputStreamReader(fileContent))) {
            while ((line = bufferedReader.readLine()) != null) {
                if (!line.isBlank()) {
                    batch.add(line.strip());
                }

                if (batch.size() % 500 == 0) {
                    addCommonPasswordsBatch(batch);
                    batch = new ArrayList<>();
                }
            }
        } catch (IOException e) {
            LOG.error("Error reading S3 object", e);
        }

        addCommonPasswordsBatch(batch);
        return null;
    }

    private void addCommonPasswordsBatch(List<String> batch) {
        try {
            commonPasswordsService.addBatchCommonPasswords(batch);
        } catch (Exception e) {
            LOG.error("Common Passwords Dynamo Table exception thrown", e);
        }
    }
}
