package uk.gov.di.orchestration.shared.validation;

import java.util.List;

public interface Validator {
    List<String> validate(Object object);
}
