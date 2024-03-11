package uk.gov.di.authentication.utils.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.S3Event;
import com.amazonaws.services.lambda.runtime.events.models.s3.S3EventNotification;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.http.AbortableInputStream;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import uk.gov.di.authentication.shared.services.CommonPasswordsService;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class S3ToDynamoDbHandlerTest {

    private S3ToDynamoDbHandler handler;
    private final CommonPasswordsService mockCommonPasswordsService =
            mock(CommonPasswordsService.class);
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
                        .getResource("common_passwords_unit_test.txt");

        var path = Paths.get(resource.toURI());
        this.mockS3TextContent = Files.readString(path, StandardCharsets.UTF_8);

        var getObjectResponse = GetObjectResponse.builder().build();
        var mockInputStream =
                new ByteArrayInputStream(mockS3TextContent.getBytes(Charset.forName("UTF-8")));
        var mockS3ObjectInputStream =
                new ResponseInputStream<>(
                        getObjectResponse, AbortableInputStream.create(mockInputStream));

        when(mockS3Client.getObject(any(GetObjectRequest.class)))
                .thenReturn(mockS3ObjectInputStream);

        this.handler = new S3ToDynamoDbHandler(mockCommonPasswordsService, mockS3Client);

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
    void shouldCallDynamoWithCorrectSetOfPasswords() {

        ArgumentCaptor<List<String>> argument = ArgumentCaptor.forClass(List.class);

        handler.handleRequest(mockS3Event, mockContext);

        var mockInputAsArray = mockS3TextContent.split("\r?\n|\r");
        var mockInputAsArrayList = new ArrayList<>(Arrays.asList(mockInputAsArray));
        mockInputAsArrayList.removeAll(Collections.singleton(null));
        mockInputAsArrayList.removeAll(Collections.singleton(""));

        int numberOfBatchWritesExpected =
                (int) (Math.ceil((double) mockInputAsArrayList.size() / LINES_PER_BATCH_WRITE));
        verify(mockCommonPasswordsService, times(numberOfBatchWritesExpected))
                .addBatchCommonPasswords(any(List.class));

        verify(mockCommonPasswordsService).addBatchCommonPasswords(argument.capture());
        assertThat(argument.getValue(), equalTo(mockInputAsArrayList));
    }
}
