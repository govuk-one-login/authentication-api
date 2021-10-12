package uk.gov.di.authentication.accountmigration;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.S3Event;
import com.amazonaws.services.lambda.runtime.events.models.s3.S3EventNotification;
import com.amazonaws.services.s3.AmazonS3Client;
import com.amazonaws.services.s3.model.S3Object;
import com.amazonaws.services.s3.model.S3ObjectInputStream;
import com.amazonaws.util.StringInputStream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import uk.gov.di.authentication.shared.entity.UserCredentials;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.io.IOException;
import java.util.List;

import static java.lang.String.format;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class DataMigrationHandlerTest {

    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final AmazonS3Client s3Client = mock(AmazonS3Client.class);
    private final Context context = mock(Context.class);

    private final DataMigrationHandler handler =
            new DataMigrationHandler(authenticationService, configurationService, s3Client);

    @BeforeEach
    public void setup() {
        when(configurationService.getTermsAndConditionsVersion()).thenReturn("1.0");
    }

    @Test
    public void testSuccessfulImportOfSingleRecord() throws IOException {
        mockCsvData(buildValidCsv(1));

        handler.handleRequest(mockS3Event(), context);

        ArgumentCaptor<List<UserCredentials>> credentials = ArgumentCaptor.forClass(List.class);
        ArgumentCaptor<List<UserProfile>> profiles = ArgumentCaptor.forClass(List.class);

        verify(authenticationService, times(1)).bulkAdd(credentials.capture(), profiles.capture());

        assertThat(credentials.getValue().size(), equalTo(1));
        assertThat(profiles.getValue().size(), equalTo(1));

        assertThat(credentials.getValue().get(0).getEmail(), equalTo("hello+0@gov.uk"));
        assertThat(profiles.getValue().get(0).getEmail(), equalTo("hello+0@gov.uk"));
    }

    @Test
    public void testSuccessfulImportOfMultipleBatches() throws IOException {
        mockCsvData(buildValidCsv(60150));

        handler.handleRequest(mockS3Event(), context);

        ArgumentCaptor<List<UserCredentials>> credentials = ArgumentCaptor.forClass(List.class);
        ArgumentCaptor<List<UserProfile>> profiles = ArgumentCaptor.forClass(List.class);

        verify(authenticationService, times(61)).bulkAdd(credentials.capture(), profiles.capture());

        assertThat(credentials.getAllValues().get(0).size(), equalTo(1000));
        assertThat(profiles.getAllValues().get(0).size(), equalTo(1000));

        assertThat(credentials.getAllValues().get(60).size(), equalTo(150));
        assertThat(profiles.getAllValues().get(60).size(), equalTo(150));
    }

    private StringBuilder buildValidCsv(int rows) {
        StringBuilder csvDataBuilder = new StringBuilder();
        csvDataBuilder.append("email,encrypted_password,phone,subject_identifier,created_at\n");
        for (int i = 0; i < rows; i++) {
            csvDataBuilder.append(
                    format(
                            "\"hello+%d@gov.uk\",\"encrypted_password\",\"+441234%06d\",\"subject_identifier\",\"2021-10-11 14:54:28.816572\"\n",
                            i, i));
        }
        return csvDataBuilder;
    }

    private void mockCsvData(StringBuilder data) throws IOException {
        S3Object file = mock(S3Object.class);
        StringInputStream testStream = new StringInputStream(data.toString());
        S3ObjectInputStream s3ObjectInputStream = mock(S3ObjectInputStream.class);
        when(s3ObjectInputStream.read(any(byte[].class), anyInt(), anyInt()))
                .thenAnswer(
                        invocation ->
                                testStream.read(
                                        invocation.getArgument(0),
                                        invocation.getArgument(1),
                                        invocation.getArgument(2)));
        when(file.getObjectContent()).thenReturn(s3ObjectInputStream);
        when(s3Client.getObject(anyString(), anyString())).thenReturn(file);
    }

    private S3Event mockS3Event() {
        S3Event event = mock(S3Event.class);
        S3EventNotification.S3EventNotificationRecord notification =
                mock(S3EventNotification.S3EventNotificationRecord.class);
        when(event.getRecords()).thenReturn(List.of(notification));
        S3EventNotification.S3Entity entity = mock(S3EventNotification.S3Entity.class);
        when(notification.getS3()).thenReturn(entity);
        S3EventNotification.S3BucketEntity bucket = mock(S3EventNotification.S3BucketEntity.class);
        S3EventNotification.S3ObjectEntity file = mock(S3EventNotification.S3ObjectEntity.class);
        when(entity.getBucket()).thenReturn(bucket);
        when(entity.getObject()).thenReturn(file);
        when(bucket.getName()).thenReturn("test-bucket");
        when(file.getKey()).thenReturn("test-file.csv");

        return event;
    }
}
