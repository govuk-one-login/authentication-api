package uk.gov.di.authentication.accountmigration;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.S3Event;
import com.amazonaws.services.lambda.runtime.events.models.s3.S3EventNotification;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.s3.model.S3Object;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.opencsv.bean.CsvToBean;
import com.opencsv.bean.CsvToBeanBuilder;
import org.apache.commons.lang3.tuple.Pair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.authentication.shared.entity.TermsAndConditions;
import uk.gov.di.authentication.shared.entity.UserCredentials;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;

import java.io.InputStreamReader;
import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;

public class DataMigrationHandler implements RequestHandler<S3Event, String> {

    private static final Logger LOG = LoggerFactory.getLogger(DataMigrationHandler.class);

    private final AuthenticationService authenticationService;
    private final ConfigurationService configurationService;
    private final AmazonS3 client;

    public DataMigrationHandler(
            AuthenticationService authenticationService,
            ConfigurationService configurationService,
            AmazonS3 client) {
        this.authenticationService = authenticationService;
        this.configurationService = configurationService;
        this.client = client;
    }

    public DataMigrationHandler() {
        this.configurationService = ConfigurationService.getInstance();
        this.authenticationService = new DynamoService(configurationService);
        this.client = AmazonS3ClientBuilder.standard().withRegion("eu-west-2").build();
    }

    @Override
    public String handleRequest(S3Event input, Context context) {
        for (S3EventNotification.S3EventNotificationRecord record : input.getRecords()) {
            String s3Key = record.getS3().getObject().getKey();
            String s3Bucket = record.getS3().getBucket().getName();

            LOG.info("New data transfer file {} detected", s3Key);

            S3Object object = client.getObject(s3Bucket, s3Key);

            InputStreamReader reader = new InputStreamReader(object.getObjectContent());
            CsvToBean<ImportRecord> importRecords =
                    new CsvToBeanBuilder<ImportRecord>(reader).withType(ImportRecord.class).build();

            final int BATCH_SIZE = 1000;
            int skip = 0;
            int count = BATCH_SIZE;

            while (count == BATCH_SIZE) {
                var importBatch =
                        importRecords.stream()
                                .skip(skip)
                                .limit(BATCH_SIZE)
                                .collect(Collectors.toList());
                count = importBatch.size();
                skip = skip + count;
                LOG.info("Read {} records", count);
                var batch =
                        buildImportBatch(
                                importBatch, configurationService.getTermsAndConditionsVersion());

                authenticationService.bulkAdd(
                        batch.stream().map(p -> p.getLeft()).collect(Collectors.toList()),
                        batch.stream().map(p -> p.getRight()).collect(Collectors.toList()));

                LOG.info("Imported {} records", count);
            }
        }

        return "Complete";
    }

    private List<Pair<UserCredentials, UserProfile>> buildImportBatch(
            List<ImportRecord> importRecords, String termsAndConditionsVersion) {
        return importRecords.stream()
                .map(
                        i -> {
                            Subject subject = new Subject();
                            String now = LocalDateTime.now().toString();
                            UserCredentials userCredentials =
                                    new UserCredentials()
                                            .setEmail(i.getEmail())
                                            .setMigratedPassword(i.getEncryptedPassword())
                                            .setCreated(i.getCreatedAt().toString())
                                            .setUpdated(now)
                                            .setSubjectID(subject.toString());

                            TermsAndConditions termsAndConditions = new TermsAndConditions();
                            termsAndConditions.setVersion(termsAndConditionsVersion);
                            termsAndConditions.setTimestamp(now);
                            UserProfile userProfile =
                                    new UserProfile()
                                            .setEmail(i.getEmail())
                                            .setSubjectID(subject.toString())
                                            .setEmailVerified(true)
                                            .setCreated(i.getCreatedAt().toString())
                                            .setUpdated(userCredentials.getUpdated())
                                            .setPublicSubjectID((new Subject()).toString())
                                            .setTermsAndConditions(termsAndConditions)
                                            .setLegacySubjectID(i.getSubjectIdentifier());

                            return Pair.of(userCredentials, userProfile);
                        })
                .collect(Collectors.toList());
    }
}
