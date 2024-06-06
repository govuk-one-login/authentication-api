package uk.gov.di.orchestration.shared.helpers;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

class ConstructUriHelperTest {

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

        assertThat(uri.toString(), equalTo("https://GOV.UK?referer=emailConfirmationEmail"));
    }

    @Test
    void shouldBeAbleToChainBuildURI() {
        var baseUrl = URI.create("https://GOV.UK/");
        var path1 = "information";
        var path2 = "user";
        var query1 = Map.of("name", "smith");
        var query2 = Map.of("dob", "2000-01-01");

        var uri = ConstructUriHelper.buildURI(baseUrl, path1, query1);
        uri = ConstructUriHelper.buildURI(uri, path2, query2);

        assertThat(
                uri.toString(),
                equalTo("https://GOV.UK/information/user?name=smith&dob=2000-01-01"));
    }

    @Test
    void shouldRemoveRedundantBackSlashes() {
        var baseUrl = URI.create("https://GOV.UK/");
        var path = "/information/";

        var uri = ConstructUriHelper.buildURI(baseUrl, path);

        assertThat(uri.toString(), equalTo("https://GOV.UK/information"));
    }
}
