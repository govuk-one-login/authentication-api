package uk.gov.di.authentication.testsupport.helpers;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import uk.gov.di.orchestration.shared.entity.AuthCodeExchangeData;
import uk.gov.di.orchestration.shared.entity.ResponseHeaders;
import uk.gov.di.orchestration.sharedtest.extensions.OrchAuthCodeExtension;

import java.net.URI;
import java.util.Optional;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertTrue;

public class OrchAuthCodeAssertionHelper {

    public static void assertOrchAuthCodeSaved(
            OrchAuthCodeExtension orchAuthCodeExtension, APIGatewayProxyResponseEvent response) {
        String responseLocationHeader = response.getHeaders().get(ResponseHeaders.LOCATION);

        assertOrchAuthCodeSaved(orchAuthCodeExtension, responseLocationHeader);
    }

    public static void assertOrchAuthCodeSaved(
            OrchAuthCodeExtension orchAuthCodeExtension, String responseLocationHeader) {
        String authCode = extractAuthCodeFromResponseLocationHeader(responseLocationHeader);

        Optional<AuthCodeExchangeData> exchangeData =
                orchAuthCodeExtension.getExchangeDataForCode(authCode);

        assertTrue(exchangeData.isPresent());
    }

    private static String extractAuthCodeFromResponseLocationHeader(String responseLocationHeader) {
        URI url = URI.create(responseLocationHeader);
        String queryParams = url.getQuery();

        String authCodePattern = "code=([^&]*)";
        var pattern = Pattern.compile(authCodePattern);
        var matcher = pattern.matcher(queryParams);

        if (matcher.find()) {
            return matcher.group(1);
        }

        return null;
    }
}
