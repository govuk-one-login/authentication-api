package uk.gov.di.orchestration.shared.aspects;

import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.reflect.MethodSignature;
import uk.gov.di.orchestration.shared.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.orchestration.shared.annotations.Instrumented;

import java.lang.reflect.Method;

import static uk.gov.di.orchestration.shared.helpers.InstrumentationHelper.segmentedFunctionCall;

/**
 * This aspect intercepts all method calls to methods annotated with @Instrumented and wraps them
 * with appropriate instrumentation.
 */
@Aspect
@ExcludeFromGeneratedCoverageReport
public class InstrumentationAspect {

    /**
     * Intercepts calls to methods annotated with @Instrumented and wraps them with instrumentation
     * code.
     *
     * @param joinPoint The join point representing the method call
     * @return The result of the method call
     * @throws Throwable If the method throws an exception
     */
    @Around("@annotation(uk.gov.di.orchestration.shared.annotations.Instrumented)")
    public Object instrumentMethod(ProceedingJoinPoint joinPoint) throws Throwable {
        MethodSignature signature = (MethodSignature) joinPoint.getSignature();
        Method method = signature.getMethod();

        // Safely get class name - handle static methods
        String className;
        if (joinPoint.getTarget() != null) {
            className = joinPoint.getTarget().getClass().getSimpleName();
        } else {
            // For static methods, get the declaring class
            className = method.getDeclaringClass().getSimpleName();
        }

        // Get the annotation and check for custom segment name
        Instrumented instrumentedAnnotation = method.getAnnotation(Instrumented.class);
        String segmentName = instrumentedAnnotation.value();

        // If no custom segment name specified, use class::method
        if (segmentName == null || segmentName.isEmpty()) {
            segmentName = className + "::" + method.getName();
        }

        // Use the unified instrumentation approach
        return segmentedFunctionCall(
                segmentName,
                () -> {
                    try {
                        return joinPoint.proceed();
                    } catch (Throwable t) {
                        if (t instanceof RuntimeException) {
                            throw (RuntimeException) t;
                        }
                        throw new RuntimeException(t);
                    }
                });
    }
}
