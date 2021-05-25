package uk.gov.di.services;

import uk.gov.di.validation.EmailValidation;
import uk.gov.di.validation.PasswordValidation;

import java.util.EnumSet;
import java.util.Set;
import java.util.regex.Pattern;

public class ValidationService {

    private static final Pattern EMAIL_REGEX = Pattern.compile("[^@]+@[^@]+\\.[^@]*");
    private static final Pattern PASSWORD_REGEX = Pattern.compile(".*\\d.*");

    public Set<EmailValidation> validateEmailAddress(String email) {
        Set<EmailValidation> emailErrors = EnumSet.noneOf(EmailValidation.class);
        if (email.isBlank()) {
            emailErrors.add(EmailValidation.EMPTY_EMAIL);
        }
        if (!email.isBlank() && !EMAIL_REGEX.matcher(email).matches()) {
            emailErrors.add(EmailValidation.INCORRECT_FORMAT);
        }
        return emailErrors;
    }

    public Set<PasswordValidation> validatePassword(String password, String retypedPassword) {
        Set<PasswordValidation> passwordErrors = EnumSet.noneOf(PasswordValidation.class);
        boolean passwordIsEmpty = false;
        boolean retypedPasswordIsEmpty = false;
        if (password == null  || password.isBlank()) {
            passwordErrors.add(PasswordValidation.EMPTY_PASSWORD_FIELD);
            passwordIsEmpty = true;
        }
        if (retypedPassword == null || retypedPassword.isBlank()) {
            passwordErrors.add(PasswordValidation.EMPTY_RETYPE_PASSWORD_FIELD);
            retypedPasswordIsEmpty = true;
        }
        if (!passwordIsEmpty && password.length() < 8) {
            passwordErrors.add(PasswordValidation.PASSWORD_TOO_SHORT);
        }
        if (!passwordIsEmpty && !PASSWORD_REGEX.matcher(password).matches()) {
            passwordErrors.add(PasswordValidation.NO_NUMBER_INCLUDED);
        }
        if (!passwordIsEmpty && !retypedPasswordIsEmpty && !password.equals(retypedPassword)) {
            passwordErrors.add(PasswordValidation.PASSWORDS_DO_NOT_MATCH);
        }
        return passwordErrors;
    }
}
