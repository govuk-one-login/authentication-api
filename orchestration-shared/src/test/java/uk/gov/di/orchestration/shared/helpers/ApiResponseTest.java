package uk.gov.di.orchestration.shared.helpers;

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
}
