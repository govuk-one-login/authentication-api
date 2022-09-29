package uk.gov.di.authentication.utils.lambda;

import com.amazonaws.http.SdkHttpMetadata;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.model.AttributeValue;
import com.amazonaws.services.dynamodbv2.model.ScanRequest;
import com.amazonaws.services.dynamodbv2.model.ScanResult;
import com.amazonaws.services.dynamodbv2.model.TransactWriteItemsRequest;
import com.amazonaws.services.dynamodbv2.model.TransactWriteItemsResult;
import com.amazonaws.services.lambda.runtime.Context;
import org.hamcrest.Description;
import org.hamcrest.TypeSafeMatcher;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import uk.gov.di.authentication.shared.entity.MFAMethod;
import uk.gov.di.authentication.shared.entity.UserCredentials;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static java.text.MessageFormat.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasEntry;
import static org.hamcrest.Matchers.hasSize;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AccountVerifierLambdaTest {

    public static final String EMAIL_ATTRIBUTE = "Email";
    public static final String EMAIL_TEMPLATE = "test{0}@example.com";
    private final AmazonDynamoDB client = mock(AmazonDynamoDB.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final AccountVerifierLambda handler =
            new AccountVerifierLambda(client, configurationService, authenticationService);

    @Test
    void shouldDoNoUpdatesWhenNothingFound() {
        when(client.scan(any(ScanRequest.class))).thenReturn(new ScanResult().withItems(List.of()));

        handler.handleRequest(10, mock(Context.class));

        verify(client, never()).transactWriteItems(any());
    }

    @Test
    void shouldWriteNewFieldWhenRecordsFoundToUpdate() {
        var email1 = getEmailAddress(1);
        var email2 = getEmailAddress(2);
        var email3 = getEmailAddress(3);
        var email4 = getEmailAddress(4);
        var profiles =
                List.of(
                        validRecord(email1, true, true),
                        validRecord(email2, false, true),
                        validRecord(email3, false, false),
                        validRecord(email4, false, false));

        when(client.scan(any(ScanRequest.class))).thenReturn(new ScanResult().withItems(profiles));

        when(authenticationService.getUserCredentialsFromEmail(email3))
                .thenReturn(userCredential(email3, true));
        when(authenticationService.getUserCredentialsFromEmail(email4))
                .thenReturn(userCredential(email4, false));

        var mockResult = generateTransactionResult(200);
        when(client.transactWriteItems(any())).thenReturn(mockResult);

        handler.handleRequest(10, mock(Context.class));

        ArgumentCaptor<TransactWriteItemsRequest> request =
                ArgumentCaptor.forClass(TransactWriteItemsRequest.class);
        verify(client).transactWriteItems(request.capture());

        assertThat(request.getValue().getTransactItems(), hasSize(2));
        assertThat(
                request.getValue().getTransactItems().get(0).getUpdate().getKey(),
                hasEntry(EMAIL_ATTRIBUTE, new AttributeValue(email2)));
        assertThat(
                request.getValue().getTransactItems().get(1).getUpdate().getKey(),
                hasEntry(EMAIL_ATTRIBUTE, new AttributeValue(email3)));
    }

    @Test
    void shouldPerformWriteRequestsInBatchesOf25() {

        var items =
                IntStream.rangeClosed(1, 110)
                        .mapToObj(i -> validRecord(getEmailAddress(i), false, true))
                        .collect(Collectors.toList());

        when(client.scan(any(ScanRequest.class)))
                .thenReturn(
                        new ScanResult()
                                .withItems(items.subList(0, 30))
                                .withLastEvaluatedKey(keyFor(getEmailAddress(30))),
                        new ScanResult()
                                .withItems(items.subList(30, 60))
                                .withLastEvaluatedKey(keyFor(getEmailAddress(60))),
                        new ScanResult()
                                .withItems(items.subList(60, 90))
                                .withLastEvaluatedKey(keyFor(getEmailAddress(90))),
                        new ScanResult().withItems(items.subList(90, 110)));

        var mockResult = generateTransactionResult(200);
        when(client.transactWriteItems(any())).thenReturn(mockResult);

        handler.handleRequest(30, mock(Context.class));

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

    private Map<String, AttributeValue> keyFor(String emailAddress) {
        return Map.of(EMAIL_ATTRIBUTE, new AttributeValue(emailAddress));
    }

    private UserCredentials userCredential(String email, boolean hasVerifiedAuthApp) {
        var credential = new UserCredentials().withEmail(email);
        if (hasVerifiedAuthApp) {
            credential.withMfaMethods(
                    List.of(
                            new MFAMethod()
                                    .withMethodVerified(true)
                                    .withEnabled(true)
                                    .withCredentialValue("a-secret-value")
                                    .withMfaMethodType("AUTH_APP")));
        }
        return credential;
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
                        format("updates for addresses [{0}]", String.join(", ", addresses)));
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

    private Map<String, AttributeValue> validRecord(
            String emailAddress, boolean accountVerified, boolean phoneVerified) {
        var record = new HashMap<String, AttributeValue>();
        record.put(EMAIL_ATTRIBUTE, new AttributeValue().withS(emailAddress));
        record.put("PhoneNumberVerified", new AttributeValue().withN(phoneVerified ? "1" : "0"));
        if (accountVerified) {
            record.put("accountVerified", new AttributeValue().withN("1"));
        }
        return record;
    }
}
