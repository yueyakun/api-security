package com.fxg.api.security.advice;

import java.io.IOException;
import java.lang.reflect.Method;
import java.lang.reflect.Type;
import java.util.Objects;

import com.fxg.api.security.annotation.Decrypt;
import com.fxg.api.security.annotation.EnableSecurity;
import com.fxg.api.security.config.ApiSecurityConfig;
import com.fxg.api.security.interceptor.AESKeyHandler;
import com.fxg.api.security.wrapper.HttpInputMessageWrapper;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.core.MethodParameter;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.RequestBodyAdvice;

@ControllerAdvice
@ConditionalOnBean(annotation = {EnableSecurity.class})
public class DecryptRequestBodyAdvice implements RequestBodyAdvice {

	private final Logger log = LoggerFactory.getLogger(this.getClass());

	@Autowired
	private ApiSecurityConfig apiSecurityConfig;

	@Override
	public boolean supports(final MethodParameter methodParameter, final Type targetType,
			final Class<? extends HttpMessageConverter<?>> converterType) {
		final Method method = methodParameter.getMethod();
		//解密 body 的前提是：method有 Decrypt 注解且开关打开
		if (Objects.nonNull(method) && method.isAnnotationPresent(Decrypt.class) && apiSecurityConfig.isOpen()) {
			return true;
		}
		return false;
	}

	@Override
	public Object handleEmptyBody(final Object body, final HttpInputMessage inputMessage, final MethodParameter parameter,
			final Type targetType, final Class<? extends HttpMessageConverter<?>> converterType) {
		return body;
	}

	@Override
	public HttpInputMessage beforeBodyRead(final HttpInputMessage inputMessage, final MethodParameter parameter, final Type targetType,
			final Class<? extends HttpMessageConverter<?>> converterType) {
		this.log("received aesKey:{}", AESKeyHandler.get());
		try {
			return new HttpInputMessageWrapper(inputMessage, apiSecurityConfig.isShowLog(),
					Objects.requireNonNull(parameter.getMethod()).getAnnotation(Decrypt.class));
		} catch (NullPointerException|IOException e) {
			log.error("Decryption failed,cause:{}", e.getMessage());
		}
		return inputMessage;
	}

	@Override
	public Object afterBodyRead(final Object body, final HttpInputMessage inputMessage, final MethodParameter parameter, final Type targetType,
			final Class<? extends HttpMessageConverter<?>> converterType) {
		return body;
	}

	private void log(final String template,final String message){
		if (this.apiSecurityConfig.isShowLog()){
			log.info(template, message);
		}
	}
}
