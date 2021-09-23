package uk.gov.di.authentication.sharedtest.httpstub;

import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

import java.util.Optional;

public class HttpProxyExtension extends HttpStubExtension implements BeforeAllCallback {
    private String currentHost;
    private String currentPort;
    private String currentNonProxyHosts;

    private void disableProxy() throws Exception {
        System.setProperty("http.proxyHost", currentHost);
        System.setProperty("http.proxyPort", currentPort);
        System.setProperty("http.nonProxyHosts", currentNonProxyHosts);
    }

    private void enableProxy() {
        currentHost = Optional.ofNullable(System.getProperty("http.proxyHost")).orElse("");
        currentPort = Optional.ofNullable(System.getProperty("http.proxyPort")).orElse("");
        currentNonProxyHosts =
                Optional.ofNullable(System.getProperty("http.nonProxyHosts")).orElse("");

        System.setProperty("http.proxyHost", "localhost");
        System.setProperty("http.proxyPort", String.valueOf(super.getHttpPort()));
        System.setProperty("http.nonProxyHosts", "localhost"); // NOT 127.0.0.1
    }

    @Override
    public void afterAll(ExtensionContext context) throws Exception {
        disableProxy();
        super.afterAll(context);
    }

    @Override
    public void beforeAll(ExtensionContext context) throws Exception {
        enableProxy();
    }
}
