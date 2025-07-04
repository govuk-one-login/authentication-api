package uk.gov.di.orchestration.shared.helpers;

import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

class ApiResponseTest {

    @Test
    void okCatchesExceptionAndReturnsAccessDenied() {

        var response =
                ApiResponse.ok(
                        () -> {
                            throw new RuntimeException();
                        });

        assertThat(response.getStatusCode(), is(400));
        assertThat(
                response.getBody(),
                is("{\"error_description\":\"Invalid request\",\"error\":\"invalid_request\"}"));
    }
}
