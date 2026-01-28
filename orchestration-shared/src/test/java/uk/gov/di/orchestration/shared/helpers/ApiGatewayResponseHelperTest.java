package uk.gov.di.orchestration.shared.helpers;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.http.HttpHeaders;
import org.junit.jupiter.api.Test;
import uk.gov.di.orchestration.shared.entity.ErrorResponse;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.collection.IsMapContaining.hasEntry;

// QualityGateUnitTest
class ApiGatewayResponseHelperTest {

    // QualityGateRegressionTest
    @Test
    void ShouldAddDefaultSecurityHeadersForErrorResponses() {
        APIGatewayProxyResponseEvent result =
                ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse(
                        404, ErrorResponse.ERROR_1000);

        assertThat(result.getHeaders(), hasEntry(HttpHeaders.CACHE_CONTROL, "no-cache, no-store"));
        assertThat(result.getHeaders(), hasEntry(HttpHeaders.PRAGMA, "no-cache"));
        assertThat(result.getHeaders(), hasEntry("X-XSS-Protection", "0"));
        assertThat(result.getHeaders(), hasEntry("X-Content-Type-Options", "nosniff"));
        assertThat(
                result.getHeaders(), hasEntry("Content-Security-Policy", "frame-ancestors 'none'"));
        assertThat(
                result.getHeaders(),
                hasEntry(
                        "Strict-Transport-Security",
                        "max-age=31536000; includeSubDomains; preload"));
        assertThat(result.getHeaders(), hasEntry("X-Frame-Options", "DENY"));
    }

    // QualityGateRegressionTest
    @Test
    void ShouldAddDefaultSecurityHeadersForSuccessResponses() {
        APIGatewayProxyResponseEvent result =
                ApiGatewayResponseHelper.generateEmptySuccessApiGatewayResponse();

        assertThat(result.getHeaders(), hasEntry(HttpHeaders.CACHE_CONTROL, "no-cache, no-store"));
        assertThat(result.getHeaders(), hasEntry(HttpHeaders.PRAGMA, "no-cache"));
        assertThat(result.getHeaders(), hasEntry("X-XSS-Protection", "0"));
        assertThat(result.getHeaders(), hasEntry("X-Content-Type-Options", "nosniff"));
        assertThat(
                result.getHeaders(), hasEntry("Content-Security-Policy", "frame-ancestors 'none'"));
        assertThat(
                result.getHeaders(),
                hasEntry(
                        "Strict-Transport-Security",
                        "max-age=31536000; includeSubDomains; preload"));
        assertThat(result.getHeaders(), hasEntry("X-Frame-Options", "DENY"));
    }

    // QualityGateRegressionTest
    @Test
    void shouldAddDefaultSecurityHeadersForAllResponses() {
        APIGatewayProxyResponseEvent result =
                ApiGatewayResponseHelper.generateApiGatewayProxyResponse(200, "test-body", null);

        assertThat(result.getHeaders(), hasEntry(HttpHeaders.CACHE_CONTROL, "no-cache, no-store"));
        assertThat(result.getHeaders(), hasEntry(HttpHeaders.PRAGMA, "no-cache"));
        assertThat(result.getHeaders(), hasEntry("X-XSS-Protection", "0"));
        assertThat(result.getHeaders(), hasEntry("X-Content-Type-Options", "nosniff"));
        assertThat(
                result.getHeaders(), hasEntry("Content-Security-Policy", "frame-ancestors 'none'"));
        assertThat(
                result.getHeaders(),
                hasEntry(
                        "Strict-Transport-Security",
                        "max-age=31536000; includeSubDomains; preload"));
        assertThat(result.getHeaders(), hasEntry("X-Frame-Options", "DENY"));
    }
}
