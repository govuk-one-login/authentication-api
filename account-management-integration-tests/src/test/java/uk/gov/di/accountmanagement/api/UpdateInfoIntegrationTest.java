package uk.gov.di.accountmanagement.api;

import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.Test;
import uk.gov.di.accountmanagement.entity.UpdateInfoRequest;
import uk.gov.di.accountmanagement.helpers.RequestHelper;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static uk.gov.di.accountmanagement.entity.UpdateInfoType.EMAIL;

public class UpdateInfoIntegrationTest {

    private static final String UPDATE_INFO_ENDPOINT = "/update-info";
    private static final String EXISTING_EMAIL_ADDRESS = "joe.bsssssloggs@digital.cabinet-office.gov.uk";
    private static final String NEW_EMAIL_ADDRESS = "joe.b@digital.cabinet-office.gov.uk";

    @Test
    public void shouldCallLoginEndpointAndReturn200WhenLoginIsSuccessful() {
        Response response =
                RequestHelper.buildRequest(
                        UPDATE_INFO_ENDPOINT,
                        new UpdateInfoRequest(EMAIL, EXISTING_EMAIL_ADDRESS, NEW_EMAIL_ADDRESS));

        assertEquals(200, response.getStatus());
    }
}
