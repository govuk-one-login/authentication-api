package uk.gov.di.authentication.shared.services;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.ConditionalCheckFailedException;
import software.amazon.awssdk.services.dynamodb.model.UpdateItemRequest;
import uk.gov.di.authentication.shared.entity.AuthenticationAttempts;
import uk.gov.di.authentication.shared.entity.CountType;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.exceptions.AuthenticationAttemptsException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AuthenticationAttemptsServiceTest {

    private static final String INTERNAL_SUBJECT_ID = "internal-sub-id";
    private static final long TTL = 1721979370L;
    private static final JourneyType JOURNEY_TYPE = JourneyType.REAUTHENTICATION;
    private static final CountType COUNT_TYPE = CountType.ENTER_EMAIL;
    private static final String INCREMENT = "SET #count = #count + :one";
    private static final String CREATE_OR_RESET = "SET #count = :one, #ttl = :ttl";

    private final DynamoDbTable<AuthenticationAttempts> table = mock(DynamoDbTable.class);
    private final DynamoDbClient dynamoDbClient = mock(DynamoDbClient.class);
    private final ConditionalCheckFailedException conditionFailure =
            ConditionalCheckFailedException.builder().build();
    private AuthenticationAttemptsService service;

    @BeforeEach
    void setUp() {
        when(table.tableName()).thenReturn("authentication-attempt-table");
        service = new AuthenticationAttemptsService(dynamoDbClient, table);
    }

    @Test
    void shouldCreateOrResetWhenIncrementConditionFails() {
        doThrow(conditionFailure)
                .doReturn(null)
                .when(dynamoDbClient)
                .updateItem(any(UpdateItemRequest.class));

        service.createOrIncrementCount(INTERNAL_SUBJECT_ID, TTL, JOURNEY_TYPE, COUNT_TYPE);

        var captor = ArgumentCaptor.forClass(UpdateItemRequest.class);
        verify(dynamoDbClient, times(2)).updateItem(captor.capture());
        var requests = captor.getAllValues();
        assertEquals(INCREMENT, requests.get(0).updateExpression());
        assertEquals(CREATE_OR_RESET, requests.get(1).updateExpression());
    }

    @Test
    void shouldRetryWhenBothConditionsFail() {
        doThrow(conditionFailure)
                .doThrow(conditionFailure)
                .doReturn(null)
                .when(dynamoDbClient)
                .updateItem(any(UpdateItemRequest.class));

        service.createOrIncrementCount(INTERNAL_SUBJECT_ID, TTL, JOURNEY_TYPE, COUNT_TYPE);

        var captor = ArgumentCaptor.forClass(UpdateItemRequest.class);
        verify(dynamoDbClient, times(3)).updateItem(captor.capture());
        var requests = captor.getAllValues();
        assertEquals(INCREMENT, requests.get(0).updateExpression());
        assertEquals(CREATE_OR_RESET, requests.get(1).updateExpression());
        assertEquals(INCREMENT, requests.get(2).updateExpression());
    }

    @Test
    void shouldThrowAfterThreeFailedAttempts() {
        doThrow(conditionFailure).when(dynamoDbClient).updateItem(any(UpdateItemRequest.class));

        var exception =
                assertThrows(
                        AuthenticationAttemptsException.class,
                        () ->
                                service.createOrIncrementCount(
                                        INTERNAL_SUBJECT_ID, TTL, JOURNEY_TYPE, COUNT_TYPE));

        assertInstanceOf(ConditionalCheckFailedException.class, exception.getCause());
        // Each of the 3 attempts makes an increment write and a create-or-reset write
        verify(dynamoDbClient, times(6)).updateItem(any(UpdateItemRequest.class));
    }
}
