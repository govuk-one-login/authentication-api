package uk.gov.di.authentication.utils.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.S3Event;
import com.amazonaws.services.lambda.runtime.events.models.s3.S3EventNotification;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.model.S3Object;
import com.amazonaws.services.s3.model.S3ObjectInputStream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import uk.gov.di.authentication.shared.services.CommonPasswordsService;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class S3ToDynamoDbHandlerTest {

    private S3ToDynamoDbHandler handler;
    private CommonPasswordsService mockCommonPasswordsService;
    private S3Event mockS3Event;
    private Context mockContext;
    private String mockS3TextContent;
    private static final int LINES_PER_BATCH_WRITE = 500;

    @BeforeEach
    void setUp() throws URISyntaxException, IOException {
        URL resource =
                Thread.currentThread()
                        .getContextClassLoader()
                        .getResource("common_passwords_unit_test.txt");

        Path path;

        path = Paths.get(resource.toURI());
        this.mockS3TextContent = Files.readString(path, StandardCharsets.UTF_8);

        InputStream mockInputStream = new ByteArrayInputStream(mockS3TextContent.getBytes());
        var mockS3ObjectInputStream = new S3ObjectInputStream(mockInputStream, null);

        var mockS3Object = mock(S3Object.class);
        when(mockS3Object.getObjectContent()).thenReturn(mockS3ObjectInputStream);

        var mockS3Client = mock(AmazonS3.class);
        when(mockS3Client.getObject("test-bucket", "test-key")).thenReturn(mockS3Object);

        this.mockCommonPasswordsService = mock(CommonPasswordsService.class);

        this.handler = new S3ToDynamoDbHandler(mockCommonPasswordsService, mockS3Client);

        this.mockS3Event = mock(S3Event.class);
        when(mockS3Event.getRecords())
                .thenReturn(List.of(mock(S3EventNotification.S3EventNotificationRecord.class)));
        when(mockS3Event.getRecords().get(0).getS3())
                .thenReturn(mock(S3EventNotification.S3Entity.class));
        when(mockS3Event.getRecords().get(0).getS3().getBucket())
                .thenReturn(mock(S3EventNotification.S3BucketEntity.class));
        when(mockS3Event.getRecords().get(0).getS3().getBucket().getName())
                .thenReturn("test-bucket");

        when(mockS3Event.getRecords().get(0).getS3().getObject())
                .thenReturn(mock(S3EventNotification.S3ObjectEntity.class));
        when(mockS3Event.getRecords().get(0).getS3().getObject().getKey()).thenReturn("test-key");

        this.mockContext = mock(Context.class);
    }

    @Test
    void shouldCallDynamoWithCorrectSetOfPasswords() {

        ArgumentCaptor<List<String>> argument = ArgumentCaptor.forClass(List.class);

        handler.handleRequest(mockS3Event, mockContext);

        String[] mockInputAsArray = mockS3TextContent.split("\r?\n|\r");
        List<String> mockInputAsArrayList = new ArrayList<>(Arrays.asList(mockInputAsArray));
        mockInputAsArrayList.removeAll(Collections.singleton(null));
        mockInputAsArrayList.removeAll(Collections.singleton(""));

        int numberOfBatchWritesExpected =
                (int) (Math.ceil((double) mockInputAsArrayList.size() / LINES_PER_BATCH_WRITE));
        verify(mockCommonPasswordsService, times(numberOfBatchWritesExpected))
                .addBatchCommonPasswords(any(List.class));

        verify(mockCommonPasswordsService).addBatchCommonPasswords(argument.capture());
        assertEquals(argument.getValue(), mockInputAsArrayList);
    }
}
