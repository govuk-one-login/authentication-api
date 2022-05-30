package uk.gov.di.authentication.shared.validation;

import java.util.List;

public interface Validator {
    List<String> validate(Object object);
}
