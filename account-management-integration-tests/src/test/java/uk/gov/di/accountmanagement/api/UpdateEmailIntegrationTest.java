package uk.gov.di.accountmanagement.api;

import com.nimbusds.oauth2.sdk.id.Subject;
import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.Test;
import uk.gov.di.accountmanagement.entity.UpdateEmailRequest;
import uk.gov.di.accountmanagement.helpers.DynamoHelper;

import java.util.Map;

import static uk.gov.di.accountmanagement.api.IntegrationTestEndpoints.ROOT_RESOURCE_URL;

public class UpdateEmailIntegrationTest {

    private static final String UPDATE_EMAIL_ENDPOINT = "/update-email";
    private static final String EXISTING_EMAIL_ADDRESS = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final String NEW_EMAIL_ADDRESS = "joe.b@digital.cabinet-office.gov.uk";
    private static final String OTP = "123456";
    private static final Subject SUBJECT = new Subject();

    @Test
    public void shouldCallLoginEndpointAndReturn204WhenLoginIsSuccessful() {
        DynamoHelper.signUp(EXISTING_EMAIL_ADDRESS, "password-1", SUBJECT);

        Response response =
                ClientBuilder.newClient()
                        .target(ROOT_RESOURCE_URL + UPDATE_EMAIL_ENDPOINT)
                        .request(MediaType.APPLICATION_JSON)
                        .headers(new MultivaluedHashMap<>())
                        .buildPost(
                                Entity.entity(
                                        new UpdateEmailRequest(
                                                EXISTING_EMAIL_ADDRESS, NEW_EMAIL_ADDRESS, OTP),
                                        MediaType.APPLICATION_JSON))
                        .property("authorizer", Map.of("principalId", SUBJECT.getValue()))
                        .invoke();

        //        TODO: This test does not work currently as the api gateway doesn't pass on the
        // authorizer property to the requestContext. We have to do this manually as the authorizer
        // is not supported in the free version of Localstack.
        //        assertEquals(204, response.getStatus());
    }
}
