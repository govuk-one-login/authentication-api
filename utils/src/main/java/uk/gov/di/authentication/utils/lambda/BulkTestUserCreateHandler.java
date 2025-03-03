package uk.gov.di.authentication.utils.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.S3Event;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import uk.gov.di.authentication.shared.entity.MFAMethod;
import uk.gov.di.authentication.shared.entity.MFAMethodType;
import uk.gov.di.authentication.shared.entity.TermsAndConditions;
import uk.gov.di.authentication.shared.entity.UserCredentials;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.helpers.Argon2EncoderHelper;
import uk.gov.di.authentication.shared.helpers.SaltHelper;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoAuthenticationService;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.segmentedFunctionCall;

public class BulkTestUserCreateHandler implements RequestHandler<S3Event, Void> {
    private static final Logger LOG = LogManager.getLogger(BulkTestUserCreateHandler.class);
    private static final String CSV_HEADER_ROW_TEXT =
            "Email,Password,Phone2FA,PhoneNumber,AuthApp2FA,AuthAppSecret";
    private final DynamoAuthenticationService dynamoAuthenticationService;
    private final S3Client client;
    private final String latestTermsAndConditions;

    public BulkTestUserCreateHandler(
            DynamoAuthenticationService dynamoAuthenticationService, S3Client client) {
        this.dynamoAuthenticationService = dynamoAuthenticationService;
        this.client = client;
        this.latestTermsAndConditions = "test-terms-and-conditions-version";
    }

    public BulkTestUserCreateHandler(ConfigurationService configurationService, S3Client client) {
        this.dynamoAuthenticationService = new DynamoAuthenticationService(configurationService);
        this.client = client;
        this.latestTermsAndConditions = configurationService.getTermsAndConditionsVersion();
    }

    public BulkTestUserCreateHandler() {
        this(
                ConfigurationService.getInstance(),
                S3Client.builder().region((Region.EU_WEST_2)).build());
    }

    @Override
    public Void handleRequest(S3Event input, Context context) {
        LOG.info(
                "Inserting test users from S3 bucket CSV into Dynamo UserProfile and UserCredentials tables");

        String bucket = input.getRecords().get(0).getS3().getBucket().getName();
        String fileKey = input.getRecords().get(0).getS3().getObject().getKey();
        var getObjectRequest = GetObjectRequest.builder().bucket(bucket).key(fileKey).build();

        ResponseInputStream<GetObjectResponse> fileContent = client.getObject(getObjectRequest);

        segmentedFunctionCall(
                "lineReader",
                () -> {
                    List<String> batch = new ArrayList<>();
                    String line;

                    try (var bufferedReader =
                            new BufferedReader(
                                    new InputStreamReader(fileContent, Charset.forName("UTF-8")))) {
                        while ((line = bufferedReader.readLine()) != null) {
                            if (!line.isBlank() && !line.equals(CSV_HEADER_ROW_TEXT)) {
                                batch.add(line.strip());
                            }

                            if (batch.size() % 500 == 0 && !batch.isEmpty()) {
                                final List<String> finalBatch = batch;
                                segmentedFunctionCall(
                                        "dbWriteFullBatch", () -> addTestUsersBatch(finalBatch));
                                batch = new ArrayList<>();
                            }
                        }
                    } catch (IOException e) {
                        LOG.error("Error reading S3 object", e);
                    }

                    final List<String> finalBatch = batch;

                    segmentedFunctionCall("dbWriteFinalBatch", () -> addTestUsersBatch(finalBatch));
                });

        return null;
    }

    private void addTestUsersBatch(List<String> batchOfIndividualUsersAsRawCsv) {
        String dateTime = LocalDateTime.now().toString();
        Map<UserProfile, UserCredentials> testUsers = new HashMap<>();

        segmentedFunctionCall(
                "parseTestUsersCsv",
                () ->
                        batchOfIndividualUsersAsRawCsv.forEach(
                                rawCsvUserString -> {
                                    String[] testUserCsvAsArray = rawCsvUserString.split(",", -1);
                                    String subjectId = new Subject().getValue();

                                    var userProfile =
                                            getUserProfileFromTestUserArrayList(
                                                    testUserCsvAsArray, dateTime, subjectId);

                                    var userCredentials =
                                            getUserCredentialsFromTestUserArrayList(
                                                    testUserCsvAsArray, dateTime, subjectId);

                                    testUsers.put(userProfile, userCredentials);
                                }));

        try {
            segmentedFunctionCall(
                    "dynamoCreateBatchTestUsers",
                    () -> dynamoAuthenticationService.createBatchTestUsers(testUsers));
        } catch (Exception e) {
            LOG.error("User Profile or Credentials Dynamo Table exception thrown", e);
        }
    }

    private UserProfile getUserProfileFromTestUserArrayList(
            String[] testUser, String dateTime, String subjectId) {
        String emailAddress = testUser[0];
        boolean isPhoneSecondAuthFactor = testUser[2].equals("1");
        var termsAndConditions = new TermsAndConditions(latestTermsAndConditions, dateTime);

        var userProfile =
                new UserProfile()
                        .withEmail(emailAddress.toLowerCase(Locale.ROOT))
                        .withSubjectID(subjectId)
                        .withEmailVerified(true)
                        .withCreated(dateTime)
                        .withUpdated(dateTime)
                        .withPublicSubjectID(new Subject().getValue())
                        .withTermsAndConditions(termsAndConditions)
                        .withLegacySubjectID(null);
        userProfile.setSalt(SaltHelper.generateNewSalt());
        userProfile.setTestUser(1);
        userProfile.setAccountVerified(1);

        if (isPhoneSecondAuthFactor) {
            String phoneNumber = testUser[3];
            userProfile.setPhoneNumber(phoneNumber);
            userProfile.setPhoneNumberVerified(true);
        }

        return userProfile;
    }

    private UserCredentials getUserCredentialsFromTestUserArrayList(
            String[] testUser, String dateTime, String subjectId) {
        var emailAddress = testUser[0];
        var plainTextPassword = testUser[1];
        boolean isAuthAppSecondAuthFactor = testUser[4].equals("1");
        var hashedPassword = hashPassword(plainTextPassword);

        var userCredentials =
                new UserCredentials()
                        .withEmail(emailAddress.toLowerCase(Locale.ROOT))
                        .withSubjectID(subjectId)
                        .withPassword(hashedPassword)
                        .withCreated(dateTime)
                        .withUpdated(dateTime);
        userCredentials.setTestUser(1);

        if (isAuthAppSecondAuthFactor) {
            String authAppSecret = testUser[5];
            List<MFAMethod> mfaMethods = new ArrayList<>();
            var authAppMfaMethod =
                    new MFAMethod(
                            MFAMethodType.AUTH_APP.getValue(), authAppSecret, true, true, dateTime);
            mfaMethods.add(authAppMfaMethod);
            userCredentials.setMfaMethods(mfaMethods);
        }

        return userCredentials;
    }

    private static String hashPassword(String password) {
        return Argon2EncoderHelper.argon2Hash(password);
    }
}
