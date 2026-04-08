package uk.gov.di.authentication.shared.services;

import com.google.gson.JsonParseException;
import net.minidev.json.JSONObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import uk.gov.di.authentication.shared.entity.State;
import uk.gov.di.authentication.shared.exceptions.UnsuccessfulAccountInterventionsResponseException;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpConnectTimeoutException;
import java.net.http.HttpResponse;
import java.util.stream.Stream;

import static java.util.Objects.isNull;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

class AccountInterventionsServiceTest {

    private static final String FIELD_INTERVENTION = "intervention";
    private static final String FIELD_UPDATED_AT = "updatedAt";
    private static final String FIELD_APPLIED_AT = "appliedAt";

    private static final String FIELD_STATE = "state";
    private static final String FIELD_BLOCKED = "blocked";
    private static final String FIELD_SUSPENDED = "suspended";
    private static final String FIELD_REPROVE_IDENTITY = "reproveIdentity";
    private static final String FIELD_RESET_PASSWORD = "resetPassword";

    @Mock private HttpResponse<String> mockResponse;
    @Mock private HttpClient httpClient;
    @Mock private ConfigurationService configurationService;

    private AccountInterventionsService service;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        service = new AccountInterventionsService(httpClient, configurationService);
        when(configurationService.getAccountInterventionServiceURI())
                .thenReturn(URI.create("https://example.com"));
        when(configurationService.getAccountInterventionServiceCallTimeout()).thenReturn(1000L);
    }

    @Test
    void testSendAccountInterventionsOutboundRequestSuccess() throws Exception {
        String accountInterventionsResponse =
                """
                        {
                            "intervention": {
                                "updatedAt": 1696969322935,
                                "appliedAt": 1696869005821,
                                "sentAt": 1696869003456,
                                "description": "AIS_USER_PASSWORD_RESET_AND_IDENTITY_REVERIFIED",
                                "reprovedIdentityAt": 1696969322935
                            },
                            "state": {
                                "blocked": true,
                                "suspended": false,
                                "reproveIdentity": true,
                                "resetPassword": false
                            }
                        }
                        """;

        when(httpClient.<String>send(any(), any())).thenReturn(mockResponse);
        when(mockResponse.statusCode()).thenReturn(200);
        when(mockResponse.body()).thenReturn(accountInterventionsResponse);

        var expectedState = new State(true, false, true, false);

        var result = service.sendAccountInterventionsOutboundRequest("123456");
        assertEquals(expectedState, result.state());
    }

    @Test
    void testSendAccountInterventionsOutboundRequestHttpError() throws Exception {
        when(httpClient.<String>send(any(), any())).thenReturn(mockResponse);
        when(mockResponse.statusCode()).thenReturn(500);
        assertThrows(
                UnsuccessfulAccountInterventionsResponseException.class,
                () -> service.sendAccountInterventionsOutboundRequest("123456"));
    }

    @Test
    void testSendAccountInterventionsOutboundRequestIOException() throws Exception {
        when(httpClient.send(any(), any())).thenThrow(new IOException());
        assertThrows(
                UnsuccessfulAccountInterventionsResponseException.class,
                () -> service.sendAccountInterventionsOutboundRequest("123456"));
    }

    @Test
    void testSendAccountInterventionsOutboundRequestInterruptedException() throws Exception {
        when(httpClient.send(any(), any()))
                .thenThrow(new InterruptedException("thread interrupted"));
        var exception =
                assertThrows(
                        UnsuccessfulAccountInterventionsResponseException.class,
                        () -> service.sendAccountInterventionsOutboundRequest("123456"));
        assertEquals(
                "Interrupted exception when attempting to call Account Interventions outbound endpoint",
                exception.getMessage());
    }

    @Test
    void testSendAccountInterventionsOutboundRequestTimeoutException() throws Exception {
        when(httpClient.send(any(), any()))
                .thenThrow(new HttpConnectTimeoutException("request timed out"));
        when(configurationService.getAccountInterventionServiceCallTimeout()).thenReturn(1000L);
        var exception =
                assertThrows(
                        UnsuccessfulAccountInterventionsResponseException.class,
                        () -> service.sendAccountInterventionsOutboundRequest("123456"));
        assertEquals(
                "Timeout when calling Account Interventions endpoint with timeout of 1000",
                exception.getMessage());
    }

    @Test
    void testSendAccountInterventionsOutboundRequestParseException() throws Exception {
        when(httpClient.send(any(), any())).thenThrow(new IOException());
        when(mockResponse.statusCode()).thenReturn(200);
        when(mockResponse.body()).thenThrow(new JsonParseException("parse-exception-message"));
        assertThrows(
                UnsuccessfulAccountInterventionsResponseException.class,
                () -> service.sendAccountInterventionsOutboundRequest("123456"));
    }

    @ParameterizedTest
    @MethodSource("missingFieldsTestCases")
    void testParseResponseWithMissingOrNullFields(
            boolean shouldSucceed, JSONObject interventionJson, JSONObject stateJson)
            throws Exception {
        var incompleteResponseContent = new JSONObject();
        if (!isNull(interventionJson))
            incompleteResponseContent.put(FIELD_INTERVENTION, interventionJson);
        if (!isNull(stateJson)) incompleteResponseContent.put(FIELD_STATE, stateJson);

        when(httpClient.<String>send(any(), any())).thenReturn(mockResponse);
        when(mockResponse.statusCode()).thenReturn(200);
        when(mockResponse.body()).thenReturn(incompleteResponseContent.toJSONString());

        if (shouldSucceed) {
            assertDoesNotThrow(() -> service.sendAccountInterventionsOutboundRequest("123456"));
        } else {
            assertThrows(
                    UnsuccessfulAccountInterventionsResponseException.class,
                    () -> service.sendAccountInterventionsOutboundRequest("123456"));
        }
    }

    private static Stream<Arguments> missingFieldsTestCases() {
        return Stream.of(
                arguments(false, null, null), // Null Intervention + Null State
                arguments(
                        false,
                        generateInterventionJson(true),
                        null), // Valid Intervention + Null State
                arguments(
                        false,
                        generateInterventionJson(true),
                        generateStateJson(
                                true, true, true, false)), // Valid Intervention + Invalid State
                arguments(
                        false,
                        null,
                        generateStateJson(
                                true, true, true, true)), // Null Intervention + Valid State
                arguments(
                        false,
                        generateInterventionJson(false),
                        generateStateJson(
                                true, true, true, true)), // Invalid Intervention + Valid State
                arguments(
                        true,
                        generateInterventionJson(true),
                        generateStateJson(
                                true, true, true, true)) // Valid Intervention + Valid State
                );
    }

    private static JSONObject generateInterventionJson(boolean withAppliedAt) {
        var interventionJson = new JSONObject();

        if (withAppliedAt) interventionJson.put(FIELD_APPLIED_AT, 1234);

        return interventionJson;
    }

    private static JSONObject generateStateJson(
            boolean withBlocked,
            boolean withSuspended,
            boolean withReproveIdentity,
            boolean withResetPassword) {
        var stateJson = new JSONObject();

        if (withBlocked) stateJson.put(FIELD_BLOCKED, true);
        if (withSuspended) stateJson.put(FIELD_SUSPENDED, true);
        if (withReproveIdentity) stateJson.put(FIELD_REPROVE_IDENTITY, true);
        if (withResetPassword) stateJson.put(FIELD_RESET_PASSWORD, true);

        return stateJson;
    }
}
