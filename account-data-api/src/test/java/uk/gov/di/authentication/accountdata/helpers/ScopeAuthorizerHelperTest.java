package uk.gov.di.authentication.accountdata.helpers;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.entity.AccountDataScope;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.authentication.accountdata.helpers.ScopeAuthorizerHelper.isScopeAuthorized;

class ScopeAuthorizerHelperTest {

    @Test
    void shouldReturnTrueWhenScopeMatches() {
        var requestContext = new APIGatewayProxyRequestEvent.ProxyRequestContext();
        requestContext.setAuthorizer(Map.of("scope", "passkey-create"));

        assertTrue(isScopeAuthorized(AccountDataScope.PASSKEY_CREATE, requestContext));
    }

    @Test
    void shouldReturnFalseWhenScopeDoesNotMatch() {
        var requestContext = new APIGatewayProxyRequestEvent.ProxyRequestContext();
        requestContext.setAuthorizer(Map.of("scope", "passkey-retrieve"));

        assertFalse(isScopeAuthorized(AccountDataScope.PASSKEY_CREATE, requestContext));
    }

    @Test
    void shouldReturnFalseWhenAuthorizerIsNull() {
        var requestContext = new APIGatewayProxyRequestEvent.ProxyRequestContext();

        assertFalse(isScopeAuthorized(AccountDataScope.PASSKEY_CREATE, requestContext));
    }

    @Test
    void shouldReturnFalseWhenScopeFieldIsMissing() {
        var requestContext = new APIGatewayProxyRequestEvent.ProxyRequestContext();
        requestContext.setAuthorizer(Map.of("principalId", "some-subject"));

        assertFalse(isScopeAuthorized(AccountDataScope.PASSKEY_CREATE, requestContext));
    }
}
