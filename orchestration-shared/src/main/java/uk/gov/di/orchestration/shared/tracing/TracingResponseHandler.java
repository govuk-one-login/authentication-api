package uk.gov.di.orchestration.shared.tracing;

import com.amazonaws.xray.entities.Subsegment;

import java.net.http.HttpResponse;
import java.util.HashMap;
import java.util.Map;

public class TracingResponseHandler<T> implements HttpResponse.BodyHandler<T> {
    private final Subsegment subsegment;
    private final HttpResponse.BodyHandler<T> inner;

    public TracingResponseHandler(Subsegment subsegment, HttpResponse.BodyHandler<T> inner) {
        this.inner = inner;
        this.subsegment = subsegment;
    }

    @Override
    public HttpResponse.BodySubscriber<T> apply(HttpResponse.ResponseInfo responseInfo) {
        addResponseInformation(subsegment, responseInfo);
        return inner.apply(responseInfo);
    }

    // Adapted from
    // https://github.com/aws/aws-xray-sdk-java/blob/master/aws-xray-recorder-sdk-apache-http/src/main/java/com/amazonaws/xray/proxies/apache/http/TracedResponseHandler.java#L39
    private static void addResponseInformation(
            Subsegment subsegment, HttpResponse.ResponseInfo response) {
        if (null == subsegment) {
            return;
        }

        Map<String, Object> responseInformation = new HashMap<>();

        int responseCode = response.statusCode();
        switch (responseCode / 100) {
            case 4:
                subsegment.setError(true);
                if (429 == responseCode) {
                    subsegment.setThrottle(true);
                }
                break;
            case 5:
                subsegment.setFault(true);
                break;
            default:
        }
        responseInformation.put("status", responseCode);

        subsegment.putHttp("response", responseInformation);
    }
}
