package uk.gov.di.accountmanagement.api;

import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.Test;
import uk.gov.di.accountmanagement.entity.AuthenticateRequest;
import uk.gov.di.accountmanagement.helpers.DynamoHelper;
import uk.gov.di.accountmanagement.helpers.RequestHelper;
import uk.gov.di.authentication.frontendapi.entity.LoginRequest;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class AuthenticateIntegrationTest extends IntegrationTestEndpoints {

    private static final String LOGIN_ENDPOINT = "/authenticate";

    @Test
    public void shouldCallLoginEndpointAndReturn204WhenLoginIsSuccessful() {
        String email = "joe.bloggs+3@digital.cabinet-office.gov.uk";
        String password = "password-1";
        DynamoHelper.signUp(email, password);

        Response response =
                RequestHelper.buildRequest(
                        LOGIN_ENDPOINT, new AuthenticateRequest(email, password));

        assertEquals(204, response.getStatus());
    }

    @Test
    public void shouldCallLoginEndpointAndReturn401henUserHasInvalidCredentials() {
        String email = "joe.bloggs+4@digital.cabinet-office.gov.uk";
        String password = "password-1";
        DynamoHelper.signUp(email, "wrong-password");

        Response response =
                RequestHelper.buildRequest(LOGIN_ENDPOINT, new LoginRequest(email, password));

        assertEquals(401, response.getStatus());
    }
}
