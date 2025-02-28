package uk.gov.di.authentication.shared.annotations;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Annotation that marks a method for automatic instrumentation. Methods annotated
 * with @Instrumented will be automatically wrapped with instrumentation code to create spans and
 * subsegments for tracing.
 */
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.METHOD})
public @interface Instrumented {
    /**
     * Optional segment name for the trace. If not specified, the segment name will be
     * ClassName::methodName
     */
    String value() default "";
}
