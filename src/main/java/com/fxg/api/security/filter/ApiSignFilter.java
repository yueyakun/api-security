package com.fxg.api.security.filter;

import com.fxg.api.security.SecretKeyConfig;
import com.fxg.api.security.interceptor.AESKeyHandler;
import com.fxg.api.security.util.Base64Util;
import com.fxg.api.security.util.RSAUtil;
import com.fxg.api.security.util.SignUtil;
import com.fxg.api.security.wrapper.RequestWrapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.util.StringUtils;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

public class ApiSignFilter implements Filter {

	private Logger logger = LoggerFactory.getLogger(this.getClass().getName());

	/**
	 * {@code 460 签名验证失败}
	 */
	public static final int SIGN_FAILED = 460;

	/**
	 * {@code 461 请求时间不合规}
	 */
	public static final int ILLEGAL_TIMESTAMP = 461;

	/**
	 * {@code 462 历史请求}
	 */
	public static final int EXISTED_REQUEST = 462;
	public static final String VERIFY_SIGNATURE_ERROR_MSG = "Signature verification failed! Cause:{}";
	public static final String VERIFY_TIMESTAMP_ERROR_MSG = "Time stamp validation failed! requestTime:{}, currentTime:{},timeOut:{}";
	public static final String NONCE_TIMESTAMP_ERROR_MSG = "nonce or timestamp are missing! nonce:{},timestamp:{}";

	private static String REDIS_KEY = "api-security:request:%s:%s";

	@Autowired
	private SecretKeyConfig secretKeyConfig;
	@Autowired
	private RedisTemplate<String, String> redisTemplate;

	@Override
	public void init(FilterConfig filterConfig) throws ServletException {

	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {

		if (request instanceof HttpServletRequest) {
			RequestWrapper requestWrapper = new RequestWrapper((HttpServletRequest) request);

			// aes时间戳
			String timestamp = requestWrapper.getHeader("X_TIMESTAMP");
			// aes随机数
			String nonce = requestWrapper.getHeader("X_NONCE");
			// 加密的aes秘钥
			String encryptedAesKey = requestWrapper.getHeader("X_EAK");//解密aes秘钥

			HttpServletResponse httpServletResponse = (HttpServletResponse) response;

			/* 若开关开启且 checkSign 为 true 进入验签逻辑，否则只解密 aesKey*/
			if (secretKeyConfig.isOpen() && secretKeyConfig.isCheckSign()) {
				//校验重放请求
				if (checkReplay(httpServletResponse, timestamp, nonce)) {
					return;
				}

				//验证签名
				boolean sign;
				try {
					sign = SignUtil.verifySign(secretKeyConfig.getPrivateKey(), timestamp, nonce, requestWrapper);
				} catch (Exception e) {
					e.printStackTrace();
					logger.error(VERIFY_SIGNATURE_ERROR_MSG, e.getCause());
					return;
				}
				if (!sign) {
					logger.warn(VERIFY_SIGNATURE_ERROR_MSG, "sign failed");
					httpServletResponse.setStatus(SIGN_FAILED);
					return;
				}

			} else {
				if (StringUtils.hasText(encryptedAesKey)) {
					byte[] aesKeyByte = new byte[0];
					try {
						aesKeyByte = RSAUtil.decrypt(Base64Util.decode(encryptedAesKey),
								secretKeyConfig.getPrivateKey());
					} catch (GeneralSecurityException e) {
						e.printStackTrace();
					}
					String aesKey = new String(aesKeyByte, StandardCharsets.UTF_8);
					AESKeyHandler.set(aesKey);
				}
			}

			chain.doFilter(requestWrapper, response);
		} else {
			chain.doFilter(request, response);
		}
	}

	//校验是否为重放请求，是重放返回true，不是返回false
	private boolean checkReplay(HttpServletResponse response, String timestamp, String nonce) {
		//时间戳和随机数缺失直接返回
		if (!StringUtils.hasText(timestamp) || !StringUtils.hasText(nonce)) {
			logger.warn(NONCE_TIMESTAMP_ERROR_MSG, nonce, timestamp);
			response.setStatus(ILLEGAL_TIMESTAMP);
			return true;
		}
		// 计算时间差
		long requestTime = Long.parseLong(timestamp);
		long currentTime = System.currentTimeMillis();
		long toleranceTime = currentTime - requestTime;
		// 如果请求时间大于当前时间或者小于最小容忍请求时间, 判定为超时
		if (requestTime > currentTime || secretKeyConfig.getTimeOut() < toleranceTime) {
			logger.warn(VERIFY_TIMESTAMP_ERROR_MSG, requestTime, currentTime, secretKeyConfig.getTimeOut());
			response.setStatus(ILLEGAL_TIMESTAMP);
			return true;
		}
		//如果timestamp和已存在,说明timeout时间内同样的报文之前请求过
		Boolean success = redisTemplate.opsForValue()
				.setIfAbsent(String.format(REDIS_KEY, timestamp, nonce), "", secretKeyConfig.getTimeOut(),
						TimeUnit.MILLISECONDS);
		if (Objects.isNull(success) || !success) {
			response.setStatus(EXISTED_REQUEST);
			return true;
		}
		return false;
	}

	@Override
	public void destroy() {

	}
}
