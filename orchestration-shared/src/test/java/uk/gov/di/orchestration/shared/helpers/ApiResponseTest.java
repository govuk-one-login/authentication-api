package uk.gov.di.orchestration.shared.helpers;

import com.nimbusds.oauth2.sdk.OAuth2Error;
import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

class ApiResponseTest {

    @Test
    void okReturnsAsExpected() {
        var response = ApiResponse.ok("test");

        assertThat(response.getStatusCode(), is(200));
        assertThat(response.getBody(), is("\"test\""));
    }

    @Test
    void badRequestReturnsAsExpected() {
        var response = ApiResponse.badRequest("error");

        assertThat(response.getStatusCode(), is(400));
        assertThat(response.getBody(), is("\"error\""));
    }

    @Test
    void badRequestWithErrorObjectReturnsAsExpected() {
        var response = ApiResponse.badRequest(OAuth2Error.INVALID_REQUEST);

        assertThat(response.getStatusCode(), is(400));
        assertThat(
                response.getBody(),
                is("{\"error_description\":\"Invalid request\",\"error\":\"invalid_request\"}"));
    }
}
