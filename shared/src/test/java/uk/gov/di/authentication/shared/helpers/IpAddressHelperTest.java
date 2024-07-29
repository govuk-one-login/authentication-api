package uk.gov.di.authentication.shared.helpers;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent.ProxyRequestContext;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent.RequestIdentity;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.services.AuditService;

import java.util.Map;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static uk.gov.di.authentication.shared.helpers.IpAddressHelper.extractIpAddress;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.*;

class IpAddressHelperTest {

    public static final String IP_1 = buildNet1Ip(1);
    public static final String IP_2 = buildNet2Ip(1);
    public static final String IP_3 = buildNet3Ip(1);

    @Test
    void shouldPreferFirstXForwardedForHeader() {
        var request = new APIGatewayProxyRequestEvent();

        request.setHeaders(
                Map.of("X-Forwarded-For", String.format("%s, %s, %s", IP_1, IP_2, IP_3)));
        request.setRequestContext(stubContextWithSourceIp());

        assertThat(extractIpAddress(request), is(IP_1));
    }

    @Test
    void shouldPreferXForwardedForOverSourceIp() {
        var request = new APIGatewayProxyRequestEvent();

        request.setHeaders(Map.of("X-Forwarded-For", IP_1));
        request.setRequestContext(stubContextWithSourceIp());

        assertThat(extractIpAddress(request), is(IP_1));
    }

    @Test
    void shouldExtractFromXForwardedHeaderRegardlessOfCase() {
        var request = new APIGatewayProxyRequestEvent();

        request.setHeaders(Map.of("x-forwarded-for", IP_1));
        request.setRequestContext(stubContextWithSourceIp());

        assertThat(extractIpAddress(request), is(IP_1));
    }

    @Test
    void shouldChooseSourceIpAsLastResort() {
        var request = new APIGatewayProxyRequestEvent();
        request.setRequestContext(stubContextWithSourceIp());

        assertThat(extractIpAddress(request), is(IP_1));
    }

    @Test
    void shouldChooseDefaultIfNeitherAvailable() {
        var request = new APIGatewayProxyRequestEvent();

        assertThat(extractIpAddress(request), is(AuditService.UNKNOWN));
    }

    private ProxyRequestContext stubContextWithSourceIp() {
        return new ProxyRequestContext().withIdentity(new RequestIdentity().withSourceIp(IP_1));
    }
}
