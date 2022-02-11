package uk.gov.di.authentication.sharedtest.matchers;

import org.apache.http.client.utils.URIBuilder;
import org.hamcrest.Description;
import org.hamcrest.Matcher;
import org.hamcrest.TypeSafeDiagnosingMatcher;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLDecoder;
import java.util.Arrays;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.hamcrest.Matchers.equalTo;
import static uk.gov.di.authentication.sharedtest.exceptions.Unchecked.unchecked;

public class UriMatcher<T> extends TypeSafeDiagnosingMatcher<URI> {

    private final String name;
    private final Function<URI, T> mapper;
    private final Matcher<T> matcher;

    private UriMatcher(String name, Function<URI, T> mapper, Matcher<T> matcher) {
        this.name = name;
        this.mapper = mapper;
        this.matcher = matcher;
    }

    @Override
    protected boolean matchesSafely(URI item, Description mismatchDescription) {
        T actual = mapper.apply(item);

        boolean matched = matcher.matches(actual);

        if (!matched) {
            mismatchDescription.appendText(description(actual));
        }

        return matched;
    }

    @Override
    public void describeTo(Description description) {
        description.appendDescriptionOf(matcher);
    }

    private String description(T value) {
        return "a URI with " + name + ": " + value;
    }

    public static UriMatcher<URI> baseUri(URI expected) {
        return new UriMatcher<>(
                "base URI",
                uri -> unchecked(new URIBuilder(uri).removeQuery().setFragment(null)::build),
                equalTo(expected));
    }

    public static UriMatcher<Map<? extends String, ? extends String>> redirectQueryParameters(
            Matcher<Map<? extends String, ? extends String>> expected) {
        return new UriMatcher<>(
                "uri query parameters",
                uri -> {
                    try {
                        return parseQueryString(uri.getRawQuery());
                    } catch (UnsupportedEncodingException e) {
                        throw new RuntimeException(e);
                    }
                },
                expected);
    }

    private static Map<String, String> parseQueryString(String queryString)
            throws UnsupportedEncodingException {
        if ((queryString == null) || (queryString.equals(""))) {
            return Map.of();
        }
        String[] params = queryString.split("&");
        return Arrays.stream(params)
                .map(p -> p.split("=", 2))
                .collect(
                        Collectors.toMap(
                                s -> URLDecoder.decode(s[0], UTF_8),
                                s -> s.length == 1 ? null : URLDecoder.decode(s[1], UTF_8)));
    }
}
