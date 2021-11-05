package uk.gov.di.authentication.shared.helpers;

import java.net.URI;
import java.util.Objects;

public class ConstructUriHelper {

    public static URI buildURI(String baseUrl, String path) {
        if (!baseUrl.endsWith("/")) {
            baseUrl = baseUrl + "/";
        }
        return Objects.isNull(path)
                ? URI.create(baseUrl)
                : URI.create(baseUrl + path.replaceAll("^/+", ""));
    }

    public static URI buildURI(String baseUrl) {
        return buildURI(baseUrl, null);
    }
}
