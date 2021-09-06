package uk.gov.di.accountmanagement.api;

import com.nimbusds.oauth2.sdk.id.Subject;
import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.Test;
import uk.gov.di.accountmanagement.entity.UpdateInfoRequest;
import uk.gov.di.accountmanagement.helpers.DynamoHelper;

import java.util.Map;

import static uk.gov.di.accountmanagement.api.IntegrationTestEndpoints.ROOT_RESOURCE_URL;
import static uk.gov.di.accountmanagement.entity.UpdateInfoType.EMAIL;

public class UpdateInfoIntegrationTest {

    private static final String UPDATE_INFO_ENDPOINT = "/update-info";
    private static final String EXISTING_EMAIL_ADDRESS = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final String NEW_EMAIL_ADDRESS = "joe.b@digital.cabinet-office.gov.uk";
    private static final Subject SUBJECT = new Subject();

    @Test
    public void shouldCallLoginEndpointAndReturn200WhenLoginIsSuccessful() {
        DynamoHelper.signUp(EXISTING_EMAIL_ADDRESS, "password-1", SUBJECT);

        Response response =
                ClientBuilder.newClient()
                        .target(ROOT_RESOURCE_URL + UPDATE_INFO_ENDPOINT)
                        .request(MediaType.APPLICATION_JSON)
                        .headers(new MultivaluedHashMap<>())
                        .buildPost(
                                Entity.entity(
                                        new UpdateInfoRequest(
                                                EMAIL, EXISTING_EMAIL_ADDRESS, NEW_EMAIL_ADDRESS),
                                        MediaType.APPLICATION_JSON))
                        .property("authorizer", Map.of("principalId", SUBJECT.getValue()))
                        .invoke();

        //        TODO: This test does not work currently as the api gateway doesn't pass on the
        // authorizer property to the requestContext. We have to do this manually as the authorizer
        // is not supported in the free version of Localstack.
        //        assertEquals(200, response.getStatus());
    }
}
