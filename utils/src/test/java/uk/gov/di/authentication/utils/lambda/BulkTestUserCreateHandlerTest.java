package uk.gov.di.authentication.utils.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.S3Event;
import com.amazonaws.services.lambda.runtime.events.models.s3.S3EventNotification;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.http.AbortableInputStream;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import uk.gov.di.authentication.shared.services.DynamoAuthenticationService;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class BulkTestUserCreateHandlerTest {

    private BulkTestUserCreateHandler handler;
    private final DynamoAuthenticationService mockDynamoAuthenticationService =
            mock(DynamoAuthenticationService.class);
    private final S3Event mockS3Event = mock(S3Event.class);
    private final Context mockContext = mock(Context.class);
    private final S3Client mockS3Client = mock(S3Client.class);
    private String mockS3TextContent;
    private static final int LINES_PER_BATCH_WRITE = 500;
    private static final String BUCKET_NAME = "test-bucket";
    private static final String BUCKET_KEY = "test-key";

    @BeforeEach
    void setUp() throws URISyntaxException, IOException {
        var resource =
                Thread.currentThread()
                        .getContextClassLoader()
                        .getResource("test_users_unit_test.txt");

        var path = Paths.get(resource.toURI());
        this.mockS3TextContent = Files.readString(path, StandardCharsets.UTF_8);

        var getObjectResponse = GetObjectResponse.builder().build();
        var mockInputStream =
                new ByteArrayInputStream(mockS3TextContent.getBytes(StandardCharsets.UTF_8));
        var mockS3ObjectInputStream =
                new ResponseInputStream<>(
                        getObjectResponse, AbortableInputStream.create(mockInputStream));

        when(mockS3Client.getObject(any(GetObjectRequest.class)))
                .thenReturn(mockS3ObjectInputStream);

        this.handler = new BulkTestUserCreateHandler(mockDynamoAuthenticationService, mockS3Client);

        when(mockS3Event.getRecords())
                .thenReturn(List.of(mock(S3EventNotification.S3EventNotificationRecord.class)));
        when(mockS3Event.getRecords().get(0).getS3())
                .thenReturn(mock(S3EventNotification.S3Entity.class));
        when(mockS3Event.getRecords().get(0).getS3().getBucket())
                .thenReturn(mock(S3EventNotification.S3BucketEntity.class));
        when(mockS3Event.getRecords().get(0).getS3().getBucket().getName()).thenReturn(BUCKET_NAME);

        when(mockS3Event.getRecords().get(0).getS3().getObject())
                .thenReturn(mock(S3EventNotification.S3ObjectEntity.class));
        when(mockS3Event.getRecords().get(0).getS3().getObject().getKey()).thenReturn(BUCKET_KEY);
    }

    @Test
    void shouldCallDynamoServiceWithCorrectNumberOfBatches() {
        handler.handleRequest(mockS3Event, mockContext);

        var mockInputAsArray = mockS3TextContent.split("\r?\n|\r");
        var mockInputAsArrayList = new ArrayList<>(Arrays.asList(mockInputAsArray));
        mockInputAsArrayList.removeAll(Collections.singleton(null));
        mockInputAsArrayList.removeAll(Collections.singleton(""));
        mockInputAsArrayList.removeAll(
                Collections.singleton(
                        "Email,Password,Phone2FA,PhoneNumber,AuthApp2FA,AuthAppSecret"));

        int numberOfBatchWritesExpected =
                (int) (Math.ceil((double) mockInputAsArrayList.size() / LINES_PER_BATCH_WRITE));
        verify(mockDynamoAuthenticationService, times(numberOfBatchWritesExpected))
                .createBatchTestUsers(anyMap());
    }
}
