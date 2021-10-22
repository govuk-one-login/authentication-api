package uk.gov.di.authentication.shared.helpers;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.net.URI;
import java.util.Objects;

public class ConstructUriHelper {
    private static final Logger LOG = LoggerFactory.getLogger(ConfigurationService.class);

    public static URI buildURI(String baseUrl, String path) {
        if (!baseUrl.endsWith("/")) {
            baseUrl = baseUrl + "/";
        }
        return Objects.isNull(path)
                ? URI.create(baseUrl)
                : URI.create(baseUrl + path.replaceAll("^/+", ""));
    }
}
