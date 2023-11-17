package uk.gov.di.orchestration.shared.validation;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.ArrayList;
import java.util.List;

import static java.lang.reflect.Modifier.isStatic;
import static java.util.Objects.isNull;
import static java.util.Objects.nonNull;

public class RequiredFieldValidator implements Validator {

    private static Logger LOG = LogManager.getLogger(RequiredFieldValidator.class);

    @Override
    public List<String> validate(Object object) {
        if (isNull(object)) throw new IllegalArgumentException("Cannot validate a null object");
        List<String> violations = new ArrayList<>();
        Class clazz = object.getClass();
        while (nonNull(clazz)) {
            violations.addAll(validateRequiredFields(object, clazz));

            clazz = clazz.getSuperclass();
        }
        return violations;
    }

    private List<String> validateRequiredFields(Object object, Class clazz) {
        List<String> violations = new ArrayList<>();
        for (var field : clazz.getDeclaredFields()) {
            if (!isStatic(field.getModifiers())) {
                var accessible = field.canAccess(object);
                try {
                    if (!accessible) field.trySetAccessible();
                    if (field.isAnnotationPresent(Required.class) && isNull(field.get(object))) {
                        violations.add(field.getName());
                    }
                } catch (IllegalAccessException e) {
                    LOG.warn("Could not validate field: {}", field.getName());
                } finally {
                    if (!accessible) field.setAccessible(false);
                }
            }
        }
        return violations;
    }
}
