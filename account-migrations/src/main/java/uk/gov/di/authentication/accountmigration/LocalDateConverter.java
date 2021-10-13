package uk.gov.di.authentication.accountmigration;

import com.opencsv.bean.AbstractBeanField;
import com.opencsv.exceptions.CsvConstraintViolationException;
import com.opencsv.exceptions.CsvDataTypeMismatchException;
import com.opencsv.exceptions.CsvRequiredFieldEmptyException;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class LocalDateConverter<T, I> extends AbstractBeanField<T, I> {

    private static final DateTimeFormatter FORMATTER =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSSSSS");

    @Override
    protected Object convert(String value)
            throws CsvDataTypeMismatchException, CsvConstraintViolationException {
        return LocalDateTime.parse(value, FORMATTER);
    }

    @Override
    protected String convertToWrite(Object value)
            throws CsvDataTypeMismatchException, CsvRequiredFieldEmptyException {
        return ((LocalDateTime) value).format(FORMATTER);
    }
}
