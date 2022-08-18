package uk.gov.di.authentication.utils.lambda;

import com.amazonaws.http.SdkHttpMetadata;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.model.AttributeValue;
import com.amazonaws.services.dynamodbv2.model.ScanResult;
import com.amazonaws.services.dynamodbv2.model.TransactWriteItemsRequest;
import com.amazonaws.services.dynamodbv2.model.TransactWriteItemsResult;
import com.amazonaws.services.lambda.runtime.Context;
import org.hamcrest.Description;
import org.hamcrest.TypeSafeMatcher;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static java.text.MessageFormat.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasEntry;
import static org.hamcrest.Matchers.hasSize;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AccountVerifierLambdaTest {

    public static final String EMAIL_ATTRIBUTE = "Email";
    public static final String EMAIL_TEMPLATE = "test{0}@example.com";
    private final AmazonDynamoDB client = mock(AmazonDynamoDB.class);
    private final AccountVerifierLambda handler = new AccountVerifierLambda(client);

    @Test
    void shouldDoNoUpdatesWhenNothingFound() {
        when(client.scan(anyString(), anyMap())).thenReturn(new ScanResult().withItems(List.of()));

        handler.handleRequest(0, mock(Context.class));

        verify(client, never()).transactWriteItems(any());
    }

    @Test
    void shouldWriteNewFieldWhenRecordsFoundToUpdate() {
        when(client.scan(anyString(), anyMap()))
                .thenReturn(
                        new ScanResult()
                                .withItems(
                                        List.of(
                                                Map.of(
                                                        EMAIL_ATTRIBUTE,
                                                        new AttributeValue()
                                                                .withS(getEmailAddress(1))),
                                                Map.of(
                                                        EMAIL_ATTRIBUTE,
                                                        new AttributeValue()
                                                                .withS(getEmailAddress(2))))));

        var mockResult = generateTransactionResult(200);
        when(client.transactWriteItems(any())).thenReturn(mockResult);

        handler.handleRequest(0, mock(Context.class));

        ArgumentCaptor<TransactWriteItemsRequest> request =
                ArgumentCaptor.forClass(TransactWriteItemsRequest.class);
        verify(client).transactWriteItems(request.capture());

        assertThat(request.getValue().getTransactItems(), hasSize(2));
        assertThat(
                request.getValue().getTransactItems().get(0).getUpdate().getKey(),
                hasEntry(EMAIL_ATTRIBUTE, new AttributeValue(getEmailAddress(1))));
        assertThat(
                request.getValue().getTransactItems().get(1).getUpdate().getKey(),
                hasEntry(EMAIL_ATTRIBUTE, new AttributeValue(getEmailAddress(2))));
    }

    @Test
    void shouldBatchWriteRequestsWhenMore() {

        var items =
                IntStream.rangeClosed(1, 110)
                        .mapToObj(
                                i ->
                                        Map.of(
                                                EMAIL_ATTRIBUTE,
                                                new AttributeValue().withS(getEmailAddress(i))))
                        .collect(Collectors.toList());

        when(client.scan(anyString(), anyMap())).thenReturn(new ScanResult().withItems(items));

        var mockResult = generateTransactionResult(200);
        when(client.transactWriteItems(any())).thenReturn(mockResult);

        handler.handleRequest(0, mock(Context.class));

        ArgumentCaptor<TransactWriteItemsRequest> request =
                ArgumentCaptor.forClass(TransactWriteItemsRequest.class);
        verify(client, times(5)).transactWriteItems(request.capture());

        assertThat(request.getAllValues().get(0).getTransactItems(), hasSize(25));
        assertThat(
                request.getAllValues().get(0),
                hasUpdatesFor(
                        IntStream.rangeClosed(1, 25)
                                .mapToObj(i -> getEmailAddress(i))
                                .collect(Collectors.toList())));

        assertThat(request.getAllValues().get(1).getTransactItems(), hasSize(25));
        assertThat(
                request.getAllValues().get(1),
                hasUpdatesFor(
                        IntStream.rangeClosed(26, 50)
                                .mapToObj(i -> getEmailAddress(i))
                                .collect(Collectors.toList())));

        assertThat(request.getAllValues().get(2).getTransactItems(), hasSize(25));
        assertThat(
                request.getAllValues().get(2),
                hasUpdatesFor(
                        IntStream.rangeClosed(51, 75)
                                .mapToObj(i -> getEmailAddress(i))
                                .collect(Collectors.toList())));

        assertThat(request.getAllValues().get(3).getTransactItems(), hasSize(25));
        assertThat(
                request.getAllValues().get(3),
                hasUpdatesFor(
                        IntStream.rangeClosed(76, 100)
                                .mapToObj(i -> getEmailAddress(i))
                                .collect(Collectors.toList())));

        assertThat(request.getAllValues().get(4).getTransactItems(), hasSize(10));
        assertThat(
                request.getAllValues().get(4),
                hasUpdatesFor(
                        IntStream.rangeClosed(101, 110)
                                .mapToObj(i -> getEmailAddress(i))
                                .collect(Collectors.toList())));
    }

    private TypeSafeMatcher<TransactWriteItemsRequest> hasUpdatesFor(List<String> addresses) {
        return new TypeSafeMatcher<TransactWriteItemsRequest>() {
            @Override
            protected boolean matchesSafely(TransactWriteItemsRequest request) {
                var updates =
                        request.getTransactItems().stream()
                                .map(item -> item.getUpdate().getKey().get(EMAIL_ATTRIBUTE).getS())
                                .collect(Collectors.toList());
                return updates.containsAll(addresses) && updates.size() == addresses.size();
            }

            @Override
            public void describeTo(Description description) {
                description.appendText(
                        format("updates for addresses [{}]", String.join(", ", addresses)));
            }
        };
    }

    private String getEmailAddress(int i) {
        return format(EMAIL_TEMPLATE, i);
    }

    private TransactWriteItemsResult generateTransactionResult(int status) {
        var result = mock(TransactWriteItemsResult.class);
        var metadata = mock(SdkHttpMetadata.class);
        when(metadata.getHttpStatusCode()).thenReturn(status);
        when(result.getSdkHttpMetadata()).thenReturn(metadata);
        return result;
    }
}
