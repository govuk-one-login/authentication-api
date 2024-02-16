package uk.gov.di.authentication.frontendapi.services;

import com.google.gson.JsonParseException;
import net.minidev.json.JSONObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import uk.gov.di.authentication.frontendapi.entity.State;
import uk.gov.di.authentication.shared.exceptions.UnsuccessfulAccountInterventionsResponseException;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpResponse;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

class AccountInterventionsServiceTest {

    private static final String FIELD_UPDATED_AT = "updatedAt";
    private static final String FIELD_APPLIED_AT = "appliedAt";
    private static final String FIELD_BLOCKED = "blocked";
    private static final String FIELD_INTERVENTION = "intervention";
    private static final String FIELD_STATE = "state";

    @Mock private HttpResponse mockResponse;

    @Mock private HttpClient httpClient;
    @Mock private ConfigurationService configurationService;

    private AccountInterventionsService service;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        service = new AccountInterventionsService(httpClient, configurationService);
        when(configurationService.getAccountInterventionServiceURI())
                .thenReturn(URI.create("https://example.com"));
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

        when(httpClient.send(any(), any())).thenReturn(mockResponse);
        when(mockResponse.statusCode()).thenReturn(200);
        when(mockResponse.body()).thenReturn(accountInterventionsResponse);

        var expectedState = new State(true, false, true, false);

        var result = service.sendAccountInterventionsOutboundRequest("123456");
        assertEquals(expectedState, result.state());
    }

    @Test
    void testSendAccountInterventionsOutboundRequestHttpError() throws Exception {
        when(httpClient.send(any(), any())).thenReturn(mockResponse);
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
    void testSendAccountInterventionsOutboundRequestParseException() throws Exception {
        when(httpClient.send(any(), any())).thenThrow(new IOException());
        when(mockResponse.statusCode()).thenReturn(200);
        when(mockResponse.body()).thenThrow(new JsonParseException("parse-exception-message"));
        assertThrows(
                UnsuccessfulAccountInterventionsResponseException.class,
                () -> service.sendAccountInterventionsOutboundRequest("123456"));
    }

    @Test
    void testParseResponseWithMissingOrNullFields() throws Exception {
        var incompleteInterventionJson = new JSONObject();
        incompleteInterventionJson.put(FIELD_UPDATED_AT, null);
        incompleteInterventionJson.put(FIELD_APPLIED_AT, null);

        var incompleteStateJson = new JSONObject();
        incompleteStateJson.put(FIELD_BLOCKED, null);

        var incompleteResponseContent = new JSONObject();
        incompleteResponseContent.put(FIELD_INTERVENTION, incompleteInterventionJson);
        incompleteResponseContent.put(FIELD_STATE, incompleteStateJson);

        when(httpClient.send(any(), any())).thenReturn(mockResponse);
        when(mockResponse.statusCode()).thenReturn(200);
        when(mockResponse.body()).thenReturn(incompleteResponseContent);

        assertThrows(
                UnsuccessfulAccountInterventionsResponseException.class,
                () -> service.sendAccountInterventionsOutboundRequest("123456"));
    }
}
