package uk.gov.di.matchers;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.hamcrest.Description;
import org.hamcrest.TypeSafeDiagnosingMatcher;

public class APIGatewayProxyResponseEventStatusMatcher extends TypeSafeDiagnosingMatcher<APIGatewayProxyResponseEvent> {

    private final int statusCode;

    public APIGatewayProxyResponseEventStatusMatcher(int statusCode) {
        this.statusCode = statusCode;
    }

    @Override
    protected boolean matchesSafely(APIGatewayProxyResponseEvent item, Description mismatchDescription) {
        boolean matched = item.getStatusCode() == statusCode;

        if (!matched) {
            mismatchDescription.appendText(descriptionWith(item.getStatusCode()));
        }

        return matched;
    }

    @Override
    public void describeTo(Description description) {
        description.appendText(descriptionWith(statusCode));
    }

    public static APIGatewayProxyResponseEventStatusMatcher hasStatus(int statusCode) {
        return new APIGatewayProxyResponseEventStatusMatcher(statusCode);
    }

    private String descriptionWith(Integer statusCode) {
        return "an APIGatewayProxyResponseEvent with status code " + statusCode;
    }
}
