package uk.gov.di.authentication.shared.helpers;

import org.apache.http.client.utils.URIBuilder;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Map;
import java.util.Objects;

public class ConstructUriHelper {

    public static URI buildURI(String baseUrl, String path, Map<String, String> queryParams) {
        if (!baseUrl.endsWith("/")) {
            baseUrl = baseUrl + "/";
        }
        var uri =
                Objects.isNull(path)
                        ? URI.create(baseUrl)
                        : URI.create(baseUrl + path.replaceAll("^/+", ""));
        try {
            var uriBuilder = new URIBuilder(uri);
            if (Objects.nonNull(queryParams)) {
                for (Map.Entry<String, String> entry : queryParams.entrySet()) {
                    uriBuilder.addParameter(entry.getKey(), entry.getValue());
                }
            }
            return uriBuilder.build();
        } catch (URISyntaxException e) {
            throw new RuntimeException("Unable to build URI", e);
        }
    }

    public static URI buildURI(String baseUrl, String path) {
        return buildURI(baseUrl, path, null);
    }

    public static URI buildURI(String baseUrl) {
        return buildURI(baseUrl, null, null);
    }
}
