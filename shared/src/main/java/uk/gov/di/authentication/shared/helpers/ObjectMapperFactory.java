package uk.gov.di.authentication.shared.helpers;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

import java.util.Objects;

public class ObjectMapperFactory {
    private static ObjectMapper objectMapper;

    public static ObjectMapper getInstance() {
        if (Objects.isNull(ObjectMapperFactory.objectMapper)) {
            ObjectMapperFactory.objectMapper =
                    JsonMapper.builder().addModule(new JavaTimeModule()).build();
        }
        return ObjectMapperFactory.objectMapper;
    }
}
