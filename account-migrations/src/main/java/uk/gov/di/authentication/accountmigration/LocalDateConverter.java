package uk.gov.di.authentication.accountmigration;

import com.opencsv.bean.AbstractBeanField;
import com.opencsv.exceptions.CsvConstraintViolationException;
import com.opencsv.exceptions.CsvDataTypeMismatchException;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class LocalDateConverter extends AbstractBeanField {
    @Override
    protected Object convert(String s)
            throws CsvDataTypeMismatchException, CsvConstraintViolationException {
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSSSSS");
        LocalDateTime parse = LocalDateTime.parse(s, formatter);
        return parse;
    }
}
