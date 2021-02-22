package com.fxg.api.security.annotation;

import com.fxg.api.security.filter.ApiSignFilter;
import org.springframework.context.annotation.Import;

import java.lang.annotation.*;

@Target({ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Inherited
@Documented
@Import({ApiSignFilter.class})
public @interface EnableSecurity {

}
