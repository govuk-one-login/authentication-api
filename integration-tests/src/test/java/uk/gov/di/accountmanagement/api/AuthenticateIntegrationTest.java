package uk.gov.di.accountmanagement.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.Test;
import uk.gov.di.accountmanagement.entity.AuthenticateRequest;
import uk.gov.di.authentication.api.IntegrationTestEndpoints;
import uk.gov.di.authentication.frontendapi.entity.LoginRequest;
import uk.gov.di.authentication.frontendapi.entity.LoginResponse;
import uk.gov.di.authentication.helpers.DynamoHelper;
import uk.gov.di.authentication.helpers.RequestHelper;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static uk.gov.di.authentication.shared.entity.SessionState.LOGGED_IN;

public class AuthenticateIntegrationTest extends IntegrationTestEndpoints {

    private static final String LOGIN_ENDPOINT = "/authenticate";
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    public void shouldCallLoginEndpointAndReturn200WhenLoginIsSuccessful() throws IOException {
        String email = "joe.bloggs+3@digital.cabinet-office.gov.uk";
        String password = "password-1";
        String phoneNumber = "01234567890";
        DynamoHelper.signUp(email, password);
        DynamoHelper.addPhoneNumber(email, phoneNumber);

        Response response =
                RequestHelper.buildRequest(
                        LOGIN_ENDPOINT, new AuthenticateRequest(email, password));

        assertEquals(200, response.getStatus());

        String responseString = response.readEntity(String.class);
        LoginResponse loginResponse = objectMapper.readValue(responseString, LoginResponse.class);
        assertEquals(LOGGED_IN, loginResponse.getSessionState());
    }

    @Test
    public void shouldCallLoginEndpointAndReturn401henUserHasInvalidCredentials()
            throws IOException {
        String email = "joe.bloggs+4@digital.cabinet-office.gov.uk";
        String password = "password-1";
        DynamoHelper.signUp(email, "wrong-password");

        Response response =
                RequestHelper.buildRequest(LOGIN_ENDPOINT, new LoginRequest(email, password));

        assertEquals(401, response.getStatus());
    }
}
