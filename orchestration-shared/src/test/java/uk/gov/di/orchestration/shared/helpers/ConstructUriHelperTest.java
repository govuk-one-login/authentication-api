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
import static org.hamcrest.Matchers.aMapWithSize;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasEntry;
import static uk.gov.di.orchestration.sharedtest.matchers.UriMatcher.baseUri;
import static uk.gov.di.orchestration.sharedtest.matchers.UriMatcher.queryParameters;

// QualityGateUnitTest
class ConstructUriHelperTest {

    private static Stream<Arguments> validVectorValues() {
        return Stream.of(
                Arguments.of("https://GOV.UK", "/information"),
                Arguments.of("https://GOV.UK/", "/information"),
                Arguments.of("https://GOV.UK", "information"));
    }

    // QualityGateRegressionTest
    @ParameterizedTest
    @MethodSource("validVectorValues")
    void shouldBuildUriWithPath(String baseUrl, String path) {
        var uri = ConstructUriHelper.buildURI(baseUrl, path);

        assertThat(uri.toString(), equalTo("https://GOV.UK/information"));
    }

    // QualityGateRegressionTest
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

    // QualityGateRegressionTest
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

    // QualityGateRegressionTest
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

    // QualityGateRegressionTest
    @ParameterizedTest
    @MethodSource("queryParameterOnlyCases")
    void constructingUriWithQueryParametersShouldReturnCorrectUri(
            String providedUri, Map<String, String> queryParameters) {
        var constructedUri = ConstructUriHelper.buildURI(providedUri, queryParameters);
        assertThat(constructedUri, baseUri(URI.create(providedUri)));
        assertThat(constructedUri, queryParameters(aMapWithSize(queryParameters.size())));
        for (var entry : queryParameters.entrySet()) {
            assertThat(constructedUri, queryParameters(hasEntry(entry.getKey(), entry.getValue())));
        }

        constructedUri = ConstructUriHelper.buildURI(URI.create(providedUri), queryParameters);
        assertThat(constructedUri, baseUri(URI.create(providedUri)));
        assertThat(constructedUri, queryParameters(aMapWithSize(queryParameters.size())));
        for (var entry : queryParameters.entrySet()) {
            assertThat(constructedUri, queryParameters(hasEntry(entry.getKey(), entry.getValue())));
        }
    }

    private static Stream<Arguments> queryParameterOnlyCases() {
        return Stream.of(
                Arguments.of("https://GOV.UK", Map.of("param1", "value1", "param2", "value2")),
                Arguments.of("https://GOV.UK/", Map.of("param1", "value1", "param2", "value2")),
                Arguments.of("https://GOV.UK/path", Map.of("param1", "value1", "param2", "value2")),
                Arguments.of(
                        "https://GOV.UK/path/", Map.of("param1", "value1", "param2", "value2")));
    }

    // QualityGateRegressionTest
    @ParameterizedTest
    @MethodSource("pathOnlyCases")
    void constructingUriWithPathShouldReturnCorrectUri(
            String providedUri, String path, String combinedUri) {
        var constructedUri = ConstructUriHelper.buildURI(providedUri, path);
        assertThat(constructedUri, equalTo(URI.create(combinedUri)));

        constructedUri = ConstructUriHelper.buildURI(URI.create(providedUri), path);
        assertThat(constructedUri, equalTo(URI.create(combinedUri)));
    }

    private static Stream<Arguments> pathOnlyCases() {
        return Stream.of(
                Arguments.of("https://GOV.UK", "path", "https://GOV.UK/path"),
                Arguments.of("https://GOV.UK/", "path", "https://GOV.UK/path"),
                Arguments.of("https://GOV.UK", "/path", "https://GOV.UK/path"),
                Arguments.of("https://GOV.UK/", "/path", "https://GOV.UK/path"),
                Arguments.of("https://GOV.UK", "path/", "https://GOV.UK/path/"),
                Arguments.of("https://GOV.UK/", "path/", "https://GOV.UK/path/"),
                Arguments.of("https://GOV.UK", "/path/", "https://GOV.UK/path/"),
                Arguments.of("https://GOV.UK/", "/path/", "https://GOV.UK/path/"),
                Arguments.of("https://GOV.UK/path1", "path2", "https://GOV.UK/path1/path2"));
    }

    // QualityGateRegressionTest
    @ParameterizedTest
    @MethodSource("pathAndQueryParameterCases")
    void constructingUriWithPathAndQueryParametersShouldReturnCorrectUri(
            String providedUri,
            String path,
            Map<String, String> queryParameters,
            String combinedUri) {
        var constructedUri = ConstructUriHelper.buildURI(providedUri, path, queryParameters);
        assertThat(constructedUri, baseUri(URI.create(combinedUri)));
        assertThat(constructedUri, queryParameters(aMapWithSize(queryParameters.size())));
        for (var entry : queryParameters.entrySet()) {
            assertThat(constructedUri, queryParameters(hasEntry(entry.getKey(), entry.getValue())));
        }

        constructedUri =
                ConstructUriHelper.buildURI(URI.create(providedUri), path, queryParameters);
        assertThat(constructedUri, baseUri(URI.create(combinedUri)));
        assertThat(constructedUri, queryParameters(aMapWithSize(queryParameters.size())));
        for (var entry : queryParameters.entrySet()) {
            assertThat(constructedUri, queryParameters(hasEntry(entry.getKey(), entry.getValue())));
        }
    }

    private static Stream<Arguments> pathAndQueryParameterCases() {
        return Stream.of(
                Arguments.of(
                        "https://GOV.UK",
                        "path",
                        Map.of("param1", "value1", "param2", "value2"),
                        "https://GOV.UK/path"),
                Arguments.of(
                        "https://GOV.UK/",
                        "path/",
                        Map.of("param1", "value1", "param2", "value2"),
                        "https://GOV.UK/path/"));
    }
}
