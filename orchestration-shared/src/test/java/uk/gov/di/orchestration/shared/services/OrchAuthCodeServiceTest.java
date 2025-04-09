package uk.gov.di.orchestration.shared.services;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.enhanced.dynamodb.Key;
import software.amazon.awssdk.enhanced.dynamodb.model.GetItemEnhancedRequest;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.DynamoDbException;
import uk.gov.di.orchestration.shared.entity.AuthCodeExchangeData;
import uk.gov.di.orchestration.shared.entity.OrchAuthCodeItem;
import uk.gov.di.orchestration.shared.exceptions.OrchAuthCodeException;
import uk.gov.di.orchestration.shared.serialization.Json;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class OrchAuthCodeServiceTest {
    private static final String CLIENT_ID = "test-client-id";
    private static final String CLIENT_SESSION_ID = "test-client-session-id";
    private static final String EMAIL = "test-email";
    private static final long AUTH_TIME = 12345L;

    private static final String AUTH_CODE = "test-auth-code";
    private static final Instant CREATION_INSTANT = Instant.parse("2025-02-01T03:04:05.678Z");
    private static final long VALID_TTL = CREATION_INSTANT.plusSeconds(100).getEpochSecond();
    private static final long EXPIRED_TTL = CREATION_INSTANT.minusSeconds(100).getEpochSecond();
    private static final Key AUTH_CODE_PARTITION_KEY =
            Key.builder().partitionValue(AUTH_CODE).build();
    private static final GetItemEnhancedRequest AUTH_CODE_GET_REQUEST =
            GetItemEnhancedRequest.builder()
                    .key(AUTH_CODE_PARTITION_KEY)
                    .consistentRead(false)
                    .build();
    private static final GetItemEnhancedRequest AUTH_CODE_GET_REQUEST_WITH_CONSISTENT_READ =
            GetItemEnhancedRequest.builder()
                    .key(AUTH_CODE_PARTITION_KEY)
                    .consistentRead(true)
                    .build();
    private static final long AUTH_CODE_EXPIRY = 123L;

    private final DynamoDbTable<OrchAuthCodeItem> table = mock(DynamoDbTable.class);
    private final DynamoDbClient dynamoDbClient = mock(DynamoDbClient.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final Json objectMapper = SerializationService.getInstance();
    private OrchAuthCodeService orchAuthCodeService;

    @BeforeEach
    void setup() {
        when(configurationService.getAuthCodeExpiry()).thenReturn(AUTH_CODE_EXPIRY);

        orchAuthCodeService =
                new OrchAuthCodeService(
                        dynamoDbClient,
                        table,
                        configurationService,
                        Clock.fixed(CREATION_INSTANT, ZoneId.systemDefault()));
    }

    @Test
    void shouldStoreOrchAuthCodeItem() throws Json.JsonException {
        AuthorizationCode authorizationCode = new AuthorizationCode();

        orchAuthCodeService.generateAndSaveAuthorisationCode(
                authorizationCode, CLIENT_ID, CLIENT_SESSION_ID, EMAIL, AUTH_TIME);

        var orchAuthCodeItemCaptor = ArgumentCaptor.forClass(OrchAuthCodeItem.class);
        verify(table).putItem(orchAuthCodeItemCaptor.capture());
        var capturedRequest = orchAuthCodeItemCaptor.getValue();

        assertNotNull(capturedRequest.getAuthCode());

        var expectedExchangeData = aAuthCodeExchangeDataEntity();
        var expectedExchangeDataSerialized = objectMapper.writeValueAsString(expectedExchangeData);
        assertEquals(expectedExchangeDataSerialized, capturedRequest.getAuthCodeExchangeData());

        assertFalse(capturedRequest.getIsUsed());

        var expectedTimeToLive = CREATION_INSTANT.plusSeconds(AUTH_CODE_EXPIRY).getEpochSecond();
        assertEquals(expectedTimeToLive, capturedRequest.getTimeToLive());
    }

    // TODO: ATO-1579: Remove this test once there is only one implementation of the
    // generateAndSaveAuthorisationCode method (currently we are overloading it).
    @Test
    void shouldStoreOrchAuthCodeItemWithoutAuthorizationCodeParameter() throws Json.JsonException {
        orchAuthCodeService.generateAndSaveAuthorisationCode(
                CLIENT_ID, CLIENT_SESSION_ID, EMAIL, AUTH_TIME);

        var orchAuthCodeItemCaptor = ArgumentCaptor.forClass(OrchAuthCodeItem.class);
        verify(table).putItem(orchAuthCodeItemCaptor.capture());
        var capturedRequest = orchAuthCodeItemCaptor.getValue();

        assertNotNull(capturedRequest.getAuthCode());

        var expectedExchangeData = aAuthCodeExchangeDataEntity();
        var expectedExchangeDataSerialized = objectMapper.writeValueAsString(expectedExchangeData);
        assertEquals(expectedExchangeDataSerialized, capturedRequest.getAuthCodeExchangeData());

        assertFalse(capturedRequest.getIsUsed());

        var expectedTimeToLive = CREATION_INSTANT.plusSeconds(AUTH_CODE_EXPIRY).getEpochSecond();
        assertEquals(expectedTimeToLive, capturedRequest.getTimeToLive());
    }

    @Test
    void shouldThrowWhenFailingToStoreOrchAuthCode() {
        AuthorizationCode authorizationCode = new AuthorizationCode();

        withFailedPut();

        assertThrows(
                OrchAuthCodeException.class,
                () ->
                        orchAuthCodeService.generateAndSaveAuthorisationCode(
                                authorizationCode, CLIENT_ID, CLIENT_SESSION_ID, EMAIL, AUTH_TIME));
    }

    @Test
    void shouldGetOrchAuthCodeExchangeDataByAuthCode() throws Json.JsonException {
        var exchangeData = aAuthCodeExchangeDataEntity();
        withValidOrchAuthCode(exchangeData);

        var actualExchangeData = orchAuthCodeService.getExchangeDataForCode(AUTH_CODE);

        assertTrue(actualExchangeData.isPresent());

        assertEquals(exchangeData.getClientId(), actualExchangeData.get().getClientId());
        assertEquals(
                exchangeData.getClientSessionId(), actualExchangeData.get().getClientSessionId());
        assertEquals(exchangeData.getEmail(), actualExchangeData.get().getEmail());
        assertEquals(exchangeData.getAuthTime(), actualExchangeData.get().getAuthTime());
    }

    @Test
    void shouldNotGetAuthCodeExchangeDataByAuthCodeWhenNoOrchAuthCodeItemExists() {
        var exchangeData = orchAuthCodeService.getExchangeDataForCode(AUTH_CODE);

        assertTrue(exchangeData.isEmpty());

        verify(table).getItem(AUTH_CODE_GET_REQUEST);
        assertGetItemCalledWithStronglyConsistentRead();
    }

    @Test
    void
            shouldRetryGetOrchAuthCodeExchangeDataByAuthCodeWithStronglyConsistentReadOnceWhenItemNotFound()
                    throws Json.JsonException {
        var exchangeData = aAuthCodeExchangeDataEntity();
        var exchangeDataSerialized = objectMapper.writeValueAsString(exchangeData);

        OrchAuthCodeItem orchAuthCodeItem =
                new OrchAuthCodeItem()
                        .withAuthCode(AUTH_CODE)
                        .withAuthCodeExchangeData(exchangeDataSerialized)
                        .withIsUsed(false)
                        .withTimeToLive(VALID_TTL);

        when(table.getItem(AUTH_CODE_GET_REQUEST)).thenReturn(null);
        when(table.getItem(AUTH_CODE_GET_REQUEST_WITH_CONSISTENT_READ))
                .thenReturn(orchAuthCodeItem);

        var actualExchangeData = orchAuthCodeService.getExchangeDataForCode(AUTH_CODE);

        assertTrue(actualExchangeData.isPresent());

        assertEquals(exchangeData.getClientId(), actualExchangeData.get().getClientId());
        assertEquals(
                exchangeData.getClientSessionId(), actualExchangeData.get().getClientSessionId());
        assertEquals(exchangeData.getEmail(), actualExchangeData.get().getEmail());
        assertEquals(exchangeData.getAuthTime(), actualExchangeData.get().getAuthTime());

        verify(table).getItem(AUTH_CODE_GET_REQUEST);
        assertGetItemCalledWithStronglyConsistentRead();
    }

    @Test
    void shouldMarkAuthCodeAsUsedAfterSuccessfullyGettingOrchAuthCodeExchangeData()
            throws Json.JsonException {
        var exchangeData = aAuthCodeExchangeDataEntity();
        withValidOrchAuthCode(exchangeData);

        orchAuthCodeService.getExchangeDataForCode(AUTH_CODE);

        var orchAuthCodeItemCaptor = ArgumentCaptor.forClass(OrchAuthCodeItem.class);
        verify(table).updateItem(orchAuthCodeItemCaptor.capture());
        var capturedRequest = orchAuthCodeItemCaptor.getValue();

        assertTrue(capturedRequest.getIsUsed());
    }

    @Test
    void shouldThrowWhenFailingToGetAuthCodeExchangeDataByAuthCode() {
        withFailedGet();

        assertThrows(
                OrchAuthCodeException.class,
                () -> orchAuthCodeService.getExchangeDataForCode(AUTH_CODE));
    }

    @Test
    void shouldThrowWhenFailingToGetAuthCodeExchangeDataByAuthCodeWithStronglyConsistentRead() {
        when(table.getItem(AUTH_CODE_GET_REQUEST)).thenReturn(null);
        withFailedGetWithStronglyConsistentRead();

        assertThrows(
                OrchAuthCodeException.class,
                () -> orchAuthCodeService.getExchangeDataForCode(AUTH_CODE));

        assertGetItemCalledWithStronglyConsistentRead();
    }

    @Test
    void shouldNotGetAuthCodeExchangeDataByAuthCodeWhenOrchAuthCodeItemExistsButIsMarkedAsUsed()
            throws Json.JsonException {
        withUsedOrchAuthCode();

        var exchangeData = orchAuthCodeService.getExchangeDataForCode(AUTH_CODE);

        assertTrue(exchangeData.isEmpty());
    }

    @Test
    void shouldNotGetAuthCodeExchangeDataByAuthCodeWhenOrchAuthCodeItemExistsButTimeToLiveExpired()
            throws Json.JsonException {
        withExpiredOrchAuthCode();

        var exchangeData = orchAuthCodeService.getExchangeDataForCode(AUTH_CODE);

        assertTrue(exchangeData.isEmpty());
    }

    @Test
    void shouldThrowWhenFailingToUpdateOrchAuthCodeItemWhenMarkingAsUsed()
            throws Json.JsonException {
        var exchangeData = aAuthCodeExchangeDataEntity();
        withValidOrchAuthCode(exchangeData);

        withFailedUpdate();

        assertThrows(
                OrchAuthCodeException.class,
                () -> orchAuthCodeService.getExchangeDataForCode(AUTH_CODE));
    }

    private AuthCodeExchangeData aAuthCodeExchangeDataEntity() {
        return new AuthCodeExchangeData()
                .setClientId(CLIENT_ID)
                .setClientSessionId(CLIENT_SESSION_ID)
                .setEmail(EMAIL)
                .setAuthTime(AUTH_TIME);
    }

    private void assertGetItemCalledWithStronglyConsistentRead() {
        verify(table).getItem(AUTH_CODE_GET_REQUEST_WITH_CONSISTENT_READ);
    }

    private void withValidOrchAuthCode(AuthCodeExchangeData exchangeData)
            throws Json.JsonException {
        var exchangeDataSerialized = objectMapper.writeValueAsString(exchangeData);

        OrchAuthCodeItem orchAuthCodeItem =
                new OrchAuthCodeItem()
                        .withAuthCode(AUTH_CODE)
                        .withAuthCodeExchangeData(exchangeDataSerialized)
                        .withIsUsed(false)
                        .withTimeToLive(VALID_TTL);

        when(table.getItem(AUTH_CODE_GET_REQUEST)).thenReturn(orchAuthCodeItem);
    }

    private void withUsedOrchAuthCode() throws Json.JsonException {
        var exchangeData = aAuthCodeExchangeDataEntity();
        var exchangeDataSerialized = objectMapper.writeValueAsString(exchangeData);

        OrchAuthCodeItem orchAuthCodeItem =
                new OrchAuthCodeItem()
                        .withAuthCode(AUTH_CODE)
                        .withAuthCodeExchangeData(exchangeDataSerialized)
                        .withIsUsed(true)
                        .withTimeToLive(VALID_TTL);

        when(table.getItem(AUTH_CODE_GET_REQUEST)).thenReturn(orchAuthCodeItem);
    }

    private void withExpiredOrchAuthCode() throws Json.JsonException {
        var exchangeData = aAuthCodeExchangeDataEntity();
        var exchangeDataSerialized = objectMapper.writeValueAsString(exchangeData);

        OrchAuthCodeItem orchAuthCodeItem =
                new OrchAuthCodeItem()
                        .withAuthCode(AUTH_CODE)
                        .withAuthCodeExchangeData(exchangeDataSerialized)
                        .withIsUsed(false)
                        .withTimeToLive(EXPIRED_TTL);

        when(table.getItem(AUTH_CODE_GET_REQUEST)).thenReturn(orchAuthCodeItem);
    }

    private void withFailedPut() {
        doThrow(DynamoDbException.builder().message("Failed to put item in table").build())
                .when(table)
                .putItem(any(OrchAuthCodeItem.class));
    }

    private void withFailedGet() {
        doThrow(DynamoDbException.builder().message("Failed to get from table").build())
                .when(table)
                .getItem(eq(AUTH_CODE_GET_REQUEST));
    }

    private void withFailedGetWithStronglyConsistentRead() {
        doThrow(
                        DynamoDbException.builder()
                                .message("Failed to get from table with strongly consistent read")
                                .build())
                .when(table)
                .getItem(eq(AUTH_CODE_GET_REQUEST_WITH_CONSISTENT_READ));
    }

    private void withFailedUpdate() {
        doThrow(DynamoDbException.builder().message("Failed to update item in table").build())
                .when(table)
                .updateItem(any(OrchAuthCodeItem.class));
    }
}
