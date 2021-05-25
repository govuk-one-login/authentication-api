package uk.gov.di.entity;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static com.fasterxml.jackson.databind.DeserializationFeature.FAIL_ON_MISSING_CREATOR_PROPERTIES;

public class VcapServices {

    private static final Logger LOG = LoggerFactory.getLogger(VcapServices.class);

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Service(Credentials credentials) {}

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Credentials(
            String host, String port, String name, String username, String password) {}

    public static Optional<Credentials> readPostgresConfiguration(String vcapServices) {
        try {
            var services =
                    new ObjectMapper()
                            .configure(FAIL_ON_MISSING_CREATOR_PROPERTIES, true)
                            .readValue(
                                    vcapServices,
                                    new TypeReference<Map<String, List<Service>>>() {});

            if (services == null || !services.containsKey("postgres")) {
                LOG.info("Unable to find 'postgres' key in VCAP_SERVICES");
                return Optional.empty();
            }

            return services.get("postgres").stream().findFirst().map(Service::credentials);

        } catch (JsonProcessingException e) {
            LOG.info("Unable to parse VCAP_SERVICES json");
            return Optional.empty();
        }
    }
}
