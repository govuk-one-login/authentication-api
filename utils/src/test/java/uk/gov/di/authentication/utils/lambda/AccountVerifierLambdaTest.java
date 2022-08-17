package uk.gov.di.authentication.utils.lambda;

import com.amazonaws.http.SdkHttpMetadata;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.model.AttributeValue;
import com.amazonaws.services.dynamodbv2.model.ScanResult;
import com.amazonaws.services.dynamodbv2.model.TransactWriteItemsRequest;
import com.amazonaws.services.dynamodbv2.model.TransactWriteItemsResult;
import com.amazonaws.services.lambda.runtime.Context;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.List;
import java.util.Map;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasEntry;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AccountVerifierLambdaTest {

    public static final String TEST_EMAIL_1 = "test1@example.com";
    public static final String TEST_EMAIL_2 = "test2@example.com";
    public static final String EMAIL_ATTRIBUTE = "Email";
    private final AmazonDynamoDB client = mock(AmazonDynamoDB.class);
    private final AccountVerifierLambda handler = new AccountVerifierLambda(client);;

    @BeforeEach
    void setUp() {

    }

    @Test
    void shouldDoNoUpdatesWhenNothingFound() {
        when(client.scan(anyString(), anyMap())).thenReturn(
                new ScanResult()
                        .withItems(List.of()));

        handler.handleRequest(0, mock(Context.class));

        verify(client, never()).transactWriteItems(any());
    }

    @Test
    void shouldWriteNewFieldWhenRecordsFoundToUpdate() {
        when(client.scan(anyString(), anyMap())).thenReturn(
                new ScanResult()
                        .withItems(List.of(
                                Map.of(EMAIL_ATTRIBUTE, new AttributeValue().withS(TEST_EMAIL_1)),
                                Map.of(EMAIL_ATTRIBUTE, new AttributeValue().withS(TEST_EMAIL_2)))));

        var mockResult = generateTransactionResult(200);
        when(client.transactWriteItems(any())).thenReturn(mockResult);

        handler.handleRequest(0, mock(Context.class));

        ArgumentCaptor<TransactWriteItemsRequest> request = ArgumentCaptor.forClass(TransactWriteItemsRequest.class);
        verify(client).transactWriteItems(request.capture());

        assertThat(request.getValue().getTransactItems().size(), equalTo(2));
        assertThat(request.getValue().getTransactItems().get(0).getUpdate().getKey(), hasEntry(EMAIL_ATTRIBUTE, new AttributeValue(TEST_EMAIL_1)));
        assertThat(request.getValue().getTransactItems().get(1).getUpdate().getKey(), hasEntry(EMAIL_ATTRIBUTE, new AttributeValue(TEST_EMAIL_2)));
    }

    private TransactWriteItemsResult generateTransactionResult(int status) {
        var result = mock(TransactWriteItemsResult.class);
        var metadata = mock(SdkHttpMetadata.class);
        when(metadata.getHttpStatusCode()).thenReturn(status);
        when(result.getSdkHttpMetadata()).thenReturn(metadata);
        return result;
    }
}