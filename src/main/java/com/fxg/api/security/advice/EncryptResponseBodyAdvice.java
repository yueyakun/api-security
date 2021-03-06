package com.fxg.api.security.advice;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fxg.api.security.annotation.EnableSecurity;
import com.fxg.api.security.annotation.Encrypt;
import com.fxg.api.security.config.ApiSecurityConfig;
import com.fxg.api.security.interceptor.AESKeyHandler;
import com.fxg.api.security.util.AESUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.core.MethodParameter;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.ResponseBodyAdvice;

import java.lang.reflect.Method;
import java.util.Objects;

@ControllerAdvice
@ConditionalOnBean(annotation = {EnableSecurity.class})
public class EncryptResponseBodyAdvice implements ResponseBodyAdvice<Object> {

	private Logger logger = LoggerFactory.getLogger(this.getClass());

	@Autowired
	private ApiSecurityConfig apiSecurityConfig;
	@Autowired
	private ObjectMapper JSON;

	@Override
	public boolean supports(MethodParameter returnType, Class<? extends HttpMessageConverter<?>> converterType) {
		Method method = returnType.getMethod();
		//解密 body 的前提是：method有 Encrypt 注解且开关打开
		return Objects.nonNull(method) && method.isAnnotationPresent(Encrypt.class) && apiSecurityConfig.isOpen();
	}

	@Override
	public Object beforeBodyWrite(Object body, MethodParameter returnType, MediaType selectedContentType,
			Class<? extends HttpMessageConverter<?>> selectedConverterType, ServerHttpRequest request,
			ServerHttpResponse response) {

		Object result = encryptBody(body);
		if (result != null)
			return result;

		return body;
	}

	private Object encryptBody(Object data) {

		String aesKey = AESKeyHandler.get();
		this.log("received aesKey:{}", aesKey);

		try {
			String content = JSON.writeValueAsString(data);
			this.log("Pre-encrypted data：{}", content);
			if (!StringUtils.hasText(aesKey)) {
				throw new RuntimeException("AES_KEY IS EMPTY!");
			}
			String result = AESUtil.encrypt(content, aesKey);
			this.log("After encryption：{}", result);
			return result;
		} catch (Exception e) {
			logger.error("Encrypted data exception", e);
		}
		return null;
	}

	private void log(String template, String message) {
		if (this.apiSecurityConfig.isShowLog()) {
			logger.info(template, message);
		}
	}
}
