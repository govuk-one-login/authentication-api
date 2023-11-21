package uk.gov.di.authentication.frontendapi.services;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import net.minidev.json.JSONObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import uk.gov.di.authentication.shared.exceptions.UnsuccessfulAccountInterventionsResponseException;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

class AccountInterventionsServiceTest {

    private static final String FIELD_UPDATED_AT = "updatedAt";
    private static final String FIELD_APPLIED_AT = "appliedAt";
    private static final String FIELD_SENT_AT = "sentAt";
    private static final String FIELD_DESCRIPTION = "description";
    private static final String FIELD_REPROVED_IDENTITY_AT = "reprovedIdentityAt";
    private static final String FIELD_RESET_PASSWORD_AT = "resetPasswordAt";
    private static final String FIELD_BLOCKED = "blocked";
    private static final String FIELD_SUSPENDED = "suspended";
    private static final String FIELD_REPROVE_IDENTITY = "reproveIdentity";
    private static final String FIELD_RESET_PASSWORD = "resetPassword";
    private static final String FIELD_INTERVENTION = "intervention";
    private static final String FIELD_STATE = "state";
    private static final String DATE_TIME = "2023-01-01T00:00:00Z";
    private static final String DESCRIPTION = "intervention-description";

    @Mock private HTTPRequest mockRequest;

    @Mock private HTTPResponse mockResponse;

    private AccountInterventionsService service;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        service = new AccountInterventionsService();
    }

    @Test
    void testSendAccountInterventionsOutboundRequestSuccess() throws Exception {
        var interventionJson = new JSONObject();
        interventionJson.put(FIELD_UPDATED_AT, DATE_TIME);
        interventionJson.put(FIELD_APPLIED_AT, DATE_TIME);
        interventionJson.put(FIELD_SENT_AT, DATE_TIME);
        interventionJson.put(FIELD_DESCRIPTION, DESCRIPTION);
        interventionJson.put(FIELD_REPROVED_IDENTITY_AT, DATE_TIME);
        interventionJson.put(FIELD_RESET_PASSWORD_AT, DATE_TIME);

        var stateJson = new JSONObject();
        stateJson.put(FIELD_BLOCKED, true);
        stateJson.put(FIELD_SUSPENDED, false);
        stateJson.put(FIELD_REPROVE_IDENTITY, true);
        stateJson.put(FIELD_RESET_PASSWORD, false);

        var responseContent = new JSONObject();
        responseContent.put(FIELD_INTERVENTION, interventionJson);
        responseContent.put(FIELD_STATE, stateJson);

        when(mockRequest.send()).thenReturn(mockResponse);
        when(mockResponse.indicatesSuccess()).thenReturn(true);
        when(mockResponse.getContentAsJSONObject()).thenReturn(responseContent);

        var result = service.sendAccountInterventionsOutboundRequest(mockRequest);
        assertNotNull(result);
        assertEquals(DATE_TIME, result.intervention().updatedAt());
        assertEquals(DATE_TIME, result.intervention().appliedAt());
        assertEquals(DATE_TIME, result.intervention().sentAt());
        assertEquals(DESCRIPTION, result.intervention().description());
        assertEquals(DATE_TIME, result.intervention().reprovedIdentityAt());
        assertEquals(DATE_TIME, result.intervention().resetPasswordAt());
        assertTrue(result.state().blocked());
        assertFalse(result.state().suspended());
        assertTrue(result.state().reproveIdentity());
        assertFalse(result.state().resetPassword());
    }

    @Test
    void testSendAccountInterventionsOutboundRequestHttpError() throws Exception {
        when(mockRequest.send()).thenReturn(mockResponse);
        when(mockResponse.indicatesSuccess()).thenReturn(false);
        assertThrows(
                UnsuccessfulAccountInterventionsResponseException.class,
                () -> service.sendAccountInterventionsOutboundRequest(mockRequest));
    }

    @Test
    void testSendAccountInterventionsOutboundRequestIOException() throws Exception {
        when(mockRequest.send()).thenThrow(new IOException());
        assertThrows(
                UnsuccessfulAccountInterventionsResponseException.class,
                () -> service.sendAccountInterventionsOutboundRequest(mockRequest));
    }

    @Test
    void testSendAccountInterventionsOutboundRequestParseException() throws Exception {
        when(mockRequest.send()).thenReturn(mockResponse);
        when(mockResponse.indicatesSuccess()).thenReturn(true);
        when(mockResponse.getContentAsJSONObject())
                .thenThrow(new ParseException("parse-exception-message"));
        assertThrows(
                UnsuccessfulAccountInterventionsResponseException.class,
                () -> service.sendAccountInterventionsOutboundRequest(mockRequest));
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

        when(mockRequest.send()).thenReturn(mockResponse);
        when(mockResponse.indicatesSuccess()).thenReturn(true);
        when(mockResponse.getContentAsJSONObject()).thenReturn(incompleteResponseContent);

        assertThrows(
                UnsuccessfulAccountInterventionsResponseException.class,
                () -> service.sendAccountInterventionsOutboundRequest(mockRequest));
    }
}
