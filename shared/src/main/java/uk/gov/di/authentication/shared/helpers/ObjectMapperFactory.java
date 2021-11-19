package uk.gov.di.authentication.shared.helpers;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.BeanDescription;
import com.fasterxml.jackson.databind.DeserializationConfig;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.deser.BeanDeserializer;
import com.fasterxml.jackson.databind.deser.BeanDeserializerBase;
import com.fasterxml.jackson.databind.deser.BeanDeserializerModifier;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.ConstraintViolationException;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.util.Objects;
import java.util.Set;

public class ObjectMapperFactory {
    private static ObjectMapper objectMapper;

    public static ObjectMapper getInstance() {
        if (Objects.isNull(ObjectMapperFactory.objectMapper)) {
            SimpleModule validationModule = new SimpleModule();
            validationModule.setDeserializerModifier(
                    new BeanDeserializerModifier() {
                        @Override
                        public JsonDeserializer<?> modifyDeserializer(
                                DeserializationConfig config,
                                BeanDescription beanDesc,
                                JsonDeserializer<?> deserializer) {
                            if (deserializer instanceof BeanDeserializer) {
                                return new ValidatingBeanDeserializer(
                                        (BeanDeserializer) deserializer);
                            }

                            return deserializer;
                        }
                    });
            ObjectMapperFactory.objectMapper =
                    JsonMapper.builder()
                            .addModule(new JavaTimeModule())
                            .addModule(validationModule)
                            .build();
        }
        return ObjectMapperFactory.objectMapper;
    }

    public static class ValidatingBeanDeserializer extends BeanDeserializer {
        private static final Logger LOGGER = LogManager.getLogger(ValidatingBeanDeserializer.class);
        private final Validator validator;

        public ValidatingBeanDeserializer(BeanDeserializerBase src) {
            super(src);
            validator = Validation.buildDefaultValidatorFactory().getValidator();
        }

        @Override
        public Object deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
            Object instance = super.deserialize(p, ctxt);
            validate(instance);

            return instance;
        }

        private void validate(Object instance) {
            Set<ConstraintViolation<Object>> violations = validator.validate(instance);
            if (violations.size() > 0) {
                violations.forEach(
                        v -> LOGGER.warn("Json validation violation: {}", v.getMessage()));
                throw new ConstraintViolationException("JSON validation error", violations);
            }
        }
    }
}
