package uk.gov.di.authentication.shared.helpers;

import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

class ConstructUriHelperTest {

    @Test
    void shouldBuildUriWhenOnlyBaseUrlIsPresent() {
        var baseUrl = "https://GOV.UK";

        var uri = ConstructUriHelper.buildURI(baseUrl);

        assertThat(uri.toString(), equalTo("https://GOV.UK/"));
    }

    @Test
    void shouldBuildUriWhenOnlyBaseUrlAndPathIsPresent() {
        var baseUrl = "https://GOV.UK";
        var path = "information";

        var uri = ConstructUriHelper.buildURI(baseUrl, path);

        assertThat(uri.toString(), equalTo("https://GOV.UK/information"));
    }

    @Test
    void shouldBuildUriWhenPathAlreadyHasALeadingSlash() {
        var baseUrl = "https://GOV.UK";
        var path = "/information";

        var uri = ConstructUriHelper.buildURI(baseUrl, path);

        assertThat(uri.toString(), equalTo("https://GOV.UK/information"));
    }

    @Test
    void shouldBuildUriWhenPathAndBaseUrlBothHaveASlash() {
        var baseUrl = "https://GOV.UK/";
        var path = "/information";

        var uri = ConstructUriHelper.buildURI(baseUrl, path);

        assertThat(uri.toString(), equalTo("https://GOV.UK/information"));
    }

    @Test
    void shouldBuildUriWhenSingleQueryParamIsPresent() {
        var baseUrl = "https://GOV.UK/";
        var path = "/information";
        var queryParams = Map.of("referer", "emailConfirmationEmail");

        var uri = ConstructUriHelper.buildURI(baseUrl, path, queryParams);

        assertThat(
                uri.toString(),
                equalTo("https://GOV.UK/information?referer=emailConfirmationEmail"));
    }

    @Test
    void shouldBuildUriWhenMultipleQueryParamsArePresent() {
        var baseUrl = "https://GOV.UK/";
        var path = "/information";
        var queryParams = new HashMap<String, String>();
        queryParams.put("referer", "emailConfirmationEmail");
        queryParams.put("extraInformation", "true");

        var uri = ConstructUriHelper.buildURI(baseUrl, path, queryParams);

        assertThat(
                uri.toString(),
                equalTo(
                        "https://GOV.UK/information?referer=emailConfirmationEmail&extraInformation=true"));
    }
}
