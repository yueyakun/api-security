package com.fxg.api.security.annotation;

import com.fxg.api.security.SecretKeyConfig;
import com.fxg.api.security.advice.DecryptRequestBodyAdvice;
import com.fxg.api.security.advice.EncryptResponseBodyAdvice;
import com.fxg.api.security.filter.ApiSignFilter;
import org.springframework.context.annotation.Import;

import java.lang.annotation.*;

@Target({ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Inherited
@Documented
@Import({SecretKeyConfig.class, ApiSignFilter.class, EncryptResponseBodyAdvice.class, DecryptRequestBodyAdvice.class})
public @interface EnableSecurity {

}
