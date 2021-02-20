package com.fxg.api.security.advice;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fxg.api.security.SecretKeyConfig;
import com.fxg.api.security.annotation.Encrypt;
import com.fxg.api.security.interceptor.AESKeyHandler;
import com.fxg.api.security.util.AESUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.MethodParameter;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.util.StringUtils;
import org.springframework.web.servlet.mvc.method.annotation.ResponseBodyAdvice;

import java.lang.reflect.Method;
import java.util.Objects;

public class EncryptResponseBodyAdvice implements ResponseBodyAdvice<Object> {


	private Logger log = LoggerFactory.getLogger(this.getClass());

	@Autowired
	private SecretKeyConfig secretKeyConfig;
	@Autowired
	private ObjectMapper JSON;

	@Override
	public boolean supports(MethodParameter returnType, Class<? extends HttpMessageConverter<?>> converterType) {
		Method method = returnType.getMethod();
		//解密 body 的前提是：method有 Encrypt 注解且开关打开
		return Objects.nonNull(method) && method.isAnnotationPresent(Encrypt.class) && secretKeyConfig.isOpen();
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
		log.info("接收到aesKey:{}", aesKey);

		try {
			String content = JSON.writeValueAsString(data);
			if (secretKeyConfig.isShowLog()) {
				log.info("Pre-encrypted data：{}", content);
			}
			if (!StringUtils.hasText(aesKey)) {
				throw new RuntimeException("AES_KEY IS EMPTY!");
			}
			String result = AESUtil.encrypt(content, aesKey);
			if (secretKeyConfig.isShowLog()) {
				log.info("After encryption：{}", result);
			}
			return result;
		} catch (Exception e) {
			log.error("Encrypted data exception", e);
		}
		return null;
	}
}
