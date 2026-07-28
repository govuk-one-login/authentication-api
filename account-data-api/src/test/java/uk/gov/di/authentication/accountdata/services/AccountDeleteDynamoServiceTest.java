package uk.gov.di.authentication.accountdata.services;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import software.amazon.awssdk.core.pagination.sync.SdkIterable;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbEnhancedClient;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.enhanced.dynamodb.Key;
import software.amazon.awssdk.enhanced.dynamodb.model.PageIterable;
import software.amazon.awssdk.enhanced.dynamodb.model.QueryEnhancedRequest;
import software.amazon.awssdk.enhanced.dynamodb.model.TransactWriteItemsEnhancedRequest;
import uk.gov.di.authentication.accountdata.entity.AuthenticatorItemKey;
import uk.gov.di.authentication.shared.entity.AccountModifiers;
import uk.gov.di.authentication.shared.entity.UserCredentials;
import uk.gov.di.authentication.shared.entity.UserProfile;

import java.util.ArrayList;
import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static software.amazon.awssdk.enhanced.dynamodb.TableSchema.fromBean;

@SuppressWarnings("unchecked")
class AccountDeleteDynamoServiceTest {

    private static final String TEST_EMAIL = "test@example.com";
    private static final String TEST_INTERNAL_PAIRWISE_ID = "urn:fdc:gov.uk:2022:test-pairwise-id";
    private static final String TEST_PUBLIC_SUBJECT_ID = "test-public-subject-id";

    private final DynamoDbTable<UserProfile> userProfileTable = mock(DynamoDbTable.class);
    private final DynamoDbTable<UserCredentials> userCredentialsTable = mock(DynamoDbTable.class);
    private final DynamoDbTable<AccountModifiers> accountModifiersTable = mock(DynamoDbTable.class);
    private final DynamoDbTable<AuthenticatorItemKey> authenticatorTable =
            mock(DynamoDbTable.class);
    private final DynamoDbEnhancedClient dynamoDbEnhancedClient =
            mock(DynamoDbEnhancedClient.class);

    private final AccountDeleteDynamoService service =
            new AccountDeleteDynamoService(
                    dynamoDbEnhancedClient,
                    userProfileTable,
                    userCredentialsTable,
                    accountModifiersTable,
                    authenticatorTable);

    private final ArgumentCaptor<TransactWriteItemsEnhancedRequest> transactionCaptor =
            ArgumentCaptor.forClass(TransactWriteItemsEnhancedRequest.class);

    @BeforeEach
    void setUp() {
        when(userProfileTable.tableSchema()).thenReturn(fromBean(UserProfile.class));
        when(userProfileTable.tableName()).thenReturn("test-user-profile");
        when(userCredentialsTable.tableSchema()).thenReturn(fromBean(UserCredentials.class));
        when(userCredentialsTable.tableName()).thenReturn("test-user-credentials");
        when(accountModifiersTable.tableSchema()).thenReturn(fromBean(AccountModifiers.class));
        when(accountModifiersTable.tableName()).thenReturn("test-account-modifiers");
        when(authenticatorTable.tableSchema()).thenReturn(fromBean(AuthenticatorItemKey.class));
        when(authenticatorTable.tableName()).thenReturn("test-authenticator");
    }

    @Test
    void shouldIncludeAuthenticatorItemsInTransactionWhenAtExactCapacity() {
        when(accountModifiersTable.getItem(any(Key.class))).thenReturn(null);
        mockAuthenticatorQuery(buildAuthenticatorItems(98));

        service.deleteAccount(TEST_EMAIL, TEST_INTERNAL_PAIRWISE_ID, TEST_PUBLIC_SUBJECT_ID);

        verify(dynamoDbEnhancedClient).transactWriteItems(transactionCaptor.capture());
        assertThat(transactionCaptor.getValue().transactWriteItems().size(), equalTo(100));
        verify(authenticatorTable, never()).deleteItem(any(Key.class));
    }

    @Test
    void shouldDeleteAuthenticatorItemsIndividuallyWhenExceedingCapacity() {
        when(accountModifiersTable.getItem(any(Key.class))).thenReturn(null);
        mockAuthenticatorQuery(buildAuthenticatorItems(99));

        service.deleteAccount(TEST_EMAIL, TEST_INTERNAL_PAIRWISE_ID, TEST_PUBLIC_SUBJECT_ID);

        verify(authenticatorTable, times(99)).deleteItem(any(Key.class));
        verify(dynamoDbEnhancedClient).transactWriteItems(transactionCaptor.capture());
        assertThat(transactionCaptor.getValue().transactWriteItems().size(), equalTo(2));
    }

    @Test
    void shouldReduceAvailableCapacityWhenAccountModifiersPresent() {
        var accountModifiers =
                new AccountModifiers()
                        .withInternalCommonSubjectIdentifier(TEST_INTERNAL_PAIRWISE_ID);
        when(accountModifiersTable.getItem(any(Key.class))).thenReturn(accountModifiers);

        // 97 items fits: 2 (profile+creds) + 1 (modifiers) + 97 = 100
        mockAuthenticatorQuery(buildAuthenticatorItems(97));

        service.deleteAccount(TEST_EMAIL, TEST_INTERNAL_PAIRWISE_ID, TEST_PUBLIC_SUBJECT_ID);

        verify(dynamoDbEnhancedClient).transactWriteItems(transactionCaptor.capture());
        assertThat(transactionCaptor.getValue().transactWriteItems().size(), equalTo(100));
        verify(authenticatorTable, never()).deleteItem(any(Key.class));
    }

    @Test
    void shouldOverflowWhenAccountModifiersPresentAndAuthenticatorItemsExceedReducedCapacity() {
        var accountModifiers =
                new AccountModifiers()
                        .withInternalCommonSubjectIdentifier(TEST_INTERNAL_PAIRWISE_ID);
        when(accountModifiersTable.getItem(any(Key.class))).thenReturn(accountModifiers);

        // 98 items exceeds: 2 (profile+creds) + 1 (modifiers) + 98 = 101 > 100
        mockAuthenticatorQuery(buildAuthenticatorItems(98));

        service.deleteAccount(TEST_EMAIL, TEST_INTERNAL_PAIRWISE_ID, TEST_PUBLIC_SUBJECT_ID);

        verify(authenticatorTable, times(98)).deleteItem(any(Key.class));
        verify(dynamoDbEnhancedClient).transactWriteItems(transactionCaptor.capture());
        assertThat(transactionCaptor.getValue().transactWriteItems().size(), equalTo(3));
    }

    private List<AuthenticatorItemKey> buildAuthenticatorItems(int count) {
        var items = new ArrayList<AuthenticatorItemKey>();
        for (int i = 0; i < count; i++) {
            var item = new AuthenticatorItemKey();
            item.setPublicSubjectId(TEST_PUBLIC_SUBJECT_ID);
            item.setSortKey("PASSKEY#credential-" + i);
            items.add(item);
        }
        return items;
    }

    private void mockAuthenticatorQuery(List<AuthenticatorItemKey> items) {
        PageIterable<AuthenticatorItemKey> pageIterable = mock(PageIterable.class);
        doReturn(pageIterable).when(authenticatorTable).query(any(QueryEnhancedRequest.class));
        SdkIterable<AuthenticatorItemKey> itemsIterable = mock(SdkIterable.class);
        doReturn(itemsIterable).when(pageIterable).items();
        when(itemsIterable.stream()).thenReturn(items.stream());
    }
}
