package uk.gov.di.authentication.userpermissions;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Indicates that the annotated element is experimental and may change or be removed in future
 * releases.
 *
 * <p>This annotation serves as a warning that the API is not yet stable and should be used with
 * caution. Methods or classes marked with this annotation may be subject to incompatible changes or
 * removal in future versions without prior notice.
 *
 * <p>Usage example:
 *
 * <pre>{@code
 * @Experimental("Will be stabilized in v2.0")
 * public Result<DecisionError, Decision> someExperimentalMethod() {
 *     // Implementation
 * }
 * }</pre>
 *
 * @since 1.0
 */
@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target({
    ElementType.METHOD,
    ElementType.TYPE,
    ElementType.CONSTRUCTOR,
    ElementType.FIELD,
    ElementType.PACKAGE
})
public @interface Experimental {
    /**
     * Optional information about why the element is experimental or when it might be stabilized.
     *
     * @return description of the experimental status
     */
    String value() default "";
}
