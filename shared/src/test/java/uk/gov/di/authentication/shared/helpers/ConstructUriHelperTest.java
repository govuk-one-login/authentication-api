package uk.gov.di.authentication.shared.helpers;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.HashMap;
import java.util.Map;
import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

class ConstructUriHelperTest {

    @Test
    void shouldBuildUriWhenOnlyBaseUrlIsPresent() {
        var baseUrl = "https://GOV.UK";

        var uri = ConstructUriHelper.buildURI(baseUrl);

        assertThat(uri.toString(), equalTo("https://GOV.UK/"));
    }

    private static Stream<Arguments> validVectorValues() {
        return Stream.of(
                Arguments.of("https://GOV.UK", "/information"),
                Arguments.of("https://GOV.UK/", "/information"),
                Arguments.of("https://GOV.UK", "information"));
    }

    @ParameterizedTest
    @MethodSource("validVectorValues")
    void shouldBuildUriWithPath(String baseUrl, String path) {
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

    @Test
    void shouldBuildUriWhenOnlyQueryParamAndBaseUrlArePreent() {
        var baseUrl = "https://GOV.UK/";
        var queryParams = Map.of("referer", "emailConfirmationEmail");

        var uri = ConstructUriHelper.buildURI(baseUrl, null, queryParams);

        assertThat(uri.toString(), equalTo("https://GOV.UK/?referer=emailConfirmationEmail"));
    }
}
