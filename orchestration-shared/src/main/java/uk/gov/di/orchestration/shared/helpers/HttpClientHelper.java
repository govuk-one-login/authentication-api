package uk.gov.di.orchestration.shared.helpers;

import io.opentelemetry.api.GlobalOpenTelemetry;
import io.opentelemetry.instrumentation.javahttpclient.JavaHttpClientTelemetry;

import java.net.http.HttpClient;

public class HttpClientHelper {
    private HttpClientHelper() {}

    public static HttpClient newInstrumentedHttpClient() {
        return JavaHttpClientTelemetry.builder(GlobalOpenTelemetry.get())
                .build()
                .newHttpClient(HttpClient.newHttpClient());
    }
}
