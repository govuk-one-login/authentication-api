package uk.gov.di.orchestration.shared.helpers;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent.ProxyRequestContext;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent.RequestIdentity;
import org.junit.jupiter.api.Test;
import uk.gov.di.orchestration.shared.services.AuditService;

import java.util.Map;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static uk.gov.di.orchestration.shared.helpers.IpAddressHelper.extractIpAddress;

// QualityGateUnitTest
class IpAddressHelperTest {

    // QualityGateRegressionTest
    @Test
    void shouldPreferCloudfrontViewerOverXForwarded() {
        var request = new APIGatewayProxyRequestEvent();

        request.setHeaders(
                Map.of(
                        "X-Forwarded-For",
                        "234.234.234.234, 123.123.123.123, 111.111.111.111",
                        "Cloudfront-Viewer-Address",
                        "222.222.222.222:222"));
        request.setRequestContext(stubContextWithSourceIp());

        assertThat(extractIpAddress(request), is("222.222.222.222"));
    }

    // QualityGateRegressionTest
    @Test
    void shouldRetrieveCloudfrontViewerCaseInsensitively() {
        var request = new APIGatewayProxyRequestEvent();

        request.setHeaders(Map.of("cloudfront-viewer-address", "222.222.222.222:222"));
        request.setRequestContext(stubContextWithSourceIp());

        assertThat(extractIpAddress(request), is("222.222.222.222"));
    }

    // QualityGateRegressionTest
    @Test
    void shouldAcceptCloudfrontViewerWithoutSourcePort() {
        var request = new APIGatewayProxyRequestEvent();

        request.setHeaders(Map.of("Cloudfront-Viewer-Address", "222.222.222.222"));
        request.setRequestContext(stubContextWithSourceIp());

        assertThat(extractIpAddress(request), is("222.222.222.222"));
    }

    // QualityGateRegressionTest
    @Test
    void shouldPreferFirstXForwardedForHeader() {
        var request = new APIGatewayProxyRequestEvent();

        request.setHeaders(
                Map.of("X-Forwarded-For", "234.234.234.234, 123.123.123.123, 111.111.111.111"));
        request.setRequestContext(stubContextWithSourceIp());

        assertThat(extractIpAddress(request), is("234.234.234.234"));
    }

    // QualityGateRegressionTest
    @Test
    void shouldPreferXForwardedForOverSourceIp() {
        var request = new APIGatewayProxyRequestEvent();

        request.setHeaders(Map.of("X-Forwarded-For", "123.123.123.123"));
        request.setRequestContext(stubContextWithSourceIp());

        assertThat(extractIpAddress(request), is("123.123.123.123"));
    }

    // QualityGateRegressionTest
    @Test
    void shouldExtractFromXForwardedHeaderRegardlessOfCase() {
        var request = new APIGatewayProxyRequestEvent();

        request.setHeaders(Map.of("x-forwarded-for", "123.123.123.123"));
        request.setRequestContext(stubContextWithSourceIp());

        assertThat(extractIpAddress(request), is("123.123.123.123"));
    }

    // QualityGateRegressionTest
    @Test
    void shouldChooseSourceIpAsLastResort() {
        var request = new APIGatewayProxyRequestEvent();
        request.setRequestContext(stubContextWithSourceIp());

        assertThat(extractIpAddress(request), is("111.111.111.111"));
    }

    // QualityGateRegressionTest
    @Test
    void shouldChooseDefaultIfNeitherAvailable() {
        var request = new APIGatewayProxyRequestEvent();

        assertThat(extractIpAddress(request), is(AuditService.UNKNOWN));
    }

    private ProxyRequestContext stubContextWithSourceIp() {
        return new ProxyRequestContext()
                .withIdentity(new RequestIdentity().withSourceIp("111.111.111.111"));
    }
}
