package uk.gov.di.orchestration.shared.helpers;

import org.apache.commons.lang3.StringUtils;
import org.apache.hc.core5.net.URIBuilder;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Map;
import java.util.Optional;

public class ConstructUriHelper {

    public static URI buildURI(URI baseUrl, String path, Map<String, String> queryParams) {
        return buildURI(baseUrl.toString(), path, queryParams);
    }

    public static URI buildURI(String baseUrl, String path, Map<String, String> queryParams) {
        return buildURI(baseUrl, Optional.ofNullable(path), Optional.ofNullable(queryParams));
    }

    public static URI buildURI(URI baseUri, Map<String, String> queryParams) {
        return buildURI(baseUri.toString(), queryParams);
    }

    public static URI buildURI(String baseUri, Map<String, String> queryParams) {
        return buildURI(baseUri, Optional.empty(), Optional.ofNullable(queryParams));
    }

    public static URI buildURI(URI baseUri, String path) {
        return buildURI(baseUri.toString(), path);
    }

    public static URI buildURI(String baseUri, String path) {
        return buildURI(baseUri, Optional.ofNullable(path), Optional.empty());
    }

    private static URI buildURI(
            String baseUri, Optional<String> path, Optional<Map<String, String>> queryParams) {
        try {
            var uriBuilder =
                    path.isEmpty()
                            ? new URIBuilder(baseUri)
                            : new URIBuilder(StringUtils.removeEnd(baseUri, "/"));
            path.ifPresent(uriBuilder::appendPath);
            queryParams.ifPresent(
                    qp -> {
                        for (var entry : qp.entrySet()) {
                            uriBuilder.addParameter(entry.getKey(), entry.getValue());
                        }
                    });
            return uriBuilder.build();
        } catch (URISyntaxException e) {
            throw new RuntimeException("Unable to build URI", e);
        }
    }
}
