package uk.gov.di.authentication.utils.lambda;

import com.amazonaws.regions.Regions;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.S3Event;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3Client;
import com.amazonaws.services.s3.model.S3Object;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
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
    private final AmazonS3 client;

    public S3ToDynamoDbHandler(CommonPasswordsService commonPasswordsService, AmazonS3 client) {
        this.commonPasswordsService = commonPasswordsService;
        this.client = client;
    }

    public S3ToDynamoDbHandler(ConfigurationService configurationService, AmazonS3 client) {
        this.commonPasswordsService = new CommonPasswordsService(configurationService);
        this.client = client;
    }

    public S3ToDynamoDbHandler() {
        this(
                ConfigurationService.getInstance(),
                AmazonS3Client.builder().withRegion(Regions.EU_WEST_2).build());
    }

    @Override
    public Void handleRequest(S3Event input, Context context) {

        var bucket = input.getRecords().get(0).getS3().getBucket().getName();
        var fileKey = input.getRecords().get(0).getS3().getObject().getKey();

        LOG.info("Using bucket:{} and fileKey:{}", bucket, fileKey);

        S3Object fileContent = client.getObject(bucket, fileKey);

        List<String> batch = new ArrayList<>();
        String line;

        try (var bufferedReader =
                new BufferedReader(new InputStreamReader(fileContent.getObjectContent()))) {
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
