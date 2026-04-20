package uk.gov.di.authentication.accountdata.helpers;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

class SubjectIdAuthorizerHelperTest {

    @Test
    void shouldReturnTrueWhenPrincipalIdMatchesPublicSubjectId() {
        var subjectId = "subject-123";
        var requestContext = requestContextWithPrincipalId(subjectId);

        var result = SubjectIdAuthorizerHelper.isSubjectIdAuthorized(subjectId, requestContext);

        assertThat(result, equalTo(true));
    }

    @Test
    void shouldReturnFalseWhenPrincipalIdDoesNotMatchPublicSubjectId() {
        var requestContext = requestContextWithPrincipalId("subject-123");

        var result =
                SubjectIdAuthorizerHelper.isSubjectIdAuthorized(
                        "different-subject", requestContext);

        assertThat(result, equalTo(false));
    }

    @Test
    void shouldReturnFalseWhenAuthorizerNotSetOnRequest() {
        var requestContext = new APIGatewayProxyRequestEvent.ProxyRequestContext();

        var result = SubjectIdAuthorizerHelper.isSubjectIdAuthorized("subject-123", requestContext);

        assertThat(result, equalTo(false));
    }

    @Test
    void shouldReturnFalseWhenPrincipalIdNotSetOnAuthorizer() {
        var requestContext = new APIGatewayProxyRequestEvent.ProxyRequestContext();
        requestContext.setAuthorizer(Map.of("foo", "bar"));

        var result = SubjectIdAuthorizerHelper.isSubjectIdAuthorized("subject-123", requestContext);

        assertThat(result, equalTo(false));
    }

    private APIGatewayProxyRequestEvent.ProxyRequestContext requestContextWithPrincipalId(
            String principalId) {
        var requestContext = new APIGatewayProxyRequestEvent.ProxyRequestContext();
        requestContext.setAuthorizer(Map.of("principalId", principalId));
        return requestContext;
    }
}
