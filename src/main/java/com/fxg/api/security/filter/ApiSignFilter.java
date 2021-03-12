package com.fxg.api.security.filter;

import com.fxg.api.security.config.ApiSecurityConfig;
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
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Enumeration;
import java.util.Objects;
import java.util.TreeMap;
import java.util.concurrent.TimeUnit;

public class ApiSignFilter implements Filter {

	private Logger logger = LoggerFactory.getLogger(this.getClass().getName());

	/**
	 * {@code 460 签名验证失败}
	 */
	public static final int SIGN_FAILED = 460;
	/**
	 * {@code 461 加密的aesKey为空}
	 */
	public static final int EAK_IS_NULL = 461;
	/**
	 * {@code 462 缺少必要的签名参数}
	 */
	public static final int REQUIRED_PARAMETERS_MISSING = 462;
	/**
	 * {@code 463 请求时间不合规}
	 */
	public static final int ILLEGAL_TIMESTAMP = 463;

	/**
	 * {@code 464 历史请求}
	 */
	public static final int EXISTED_REQUEST = 464;


	private static String REDIS_KEY = "api-security:request:%s:%s";

	@Autowired
	private ApiSecurityConfig apiSecurityConfig;
	@Autowired
	private RedisTemplate<String, String> redisTemplate;

	@Override
	public void init(FilterConfig filterConfig) throws ServletException {

	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {

		if (apiSecurityConfig.isOpen() && request instanceof HttpServletRequest) {
			RequestWrapper requestWrapper = new RequestWrapper((HttpServletRequest) request);
			HttpServletResponse httpServletResponse = (HttpServletResponse) response;

			// aes时间戳
			String timestamp = requestWrapper.getHeader("X_TIMESTAMP");
			// aes随机数
			String nonce = requestWrapper.getHeader("X_NONCE");
			// 加密的aes秘钥
			String encryptedAesKey = requestWrapper.getHeader("X_EAK");
			// 请求头中的签名
			String paramSign = requestWrapper.getHeader("X_SIGN");

			// 解密aes秘钥
			if (!StringUtils.hasText(encryptedAesKey)) {
				logger.error("Encrypted aesKey can not be null! encryptedAesKey:{}", encryptedAesKey);
				httpServletResponse.setStatus(EAK_IS_NULL);
				return;
			}
			byte[] aesKeyByte;
			try {
				aesKeyByte = RSAUtil.decrypt(Base64Util.decode(encryptedAesKey), apiSecurityConfig.getPrivateKey());
			} catch (GeneralSecurityException e) {
				logger.error("Decrypt aesKey failure! Exception message:{}", e.getMessage());
				e.printStackTrace();
				return;
			}
			String aesKey = new String(aesKeyByte, StandardCharsets.UTF_8);

			AESKeyHandler.set(aesKey);

			if (apiSecurityConfig.isCheckSign()) {
				//参数校验
				if (!StringUtils.hasText(timestamp) || !StringUtils.hasText(nonce) || !StringUtils.hasText(paramSign)) {
					logger.error("Some required parameter is missing! nonce:{},timestamp:{},paramSign:{}", nonce,
							timestamp, paramSign);
					httpServletResponse.setStatus(REQUIRED_PARAMETERS_MISSING);
					return;
				}
				//校验重放请求
				if (checkReplay(httpServletResponse, timestamp, nonce)) {
					return;
				}
				// 组装签名参数
				TreeMap<String, String> params = new TreeMap<>();
				params.put("timestamp", timestamp);
				params.put("nonce", nonce);
				params.put("aesKey", aesKey);
				params.put("body", requestWrapper.getBody());
				Enumeration<String> enu = requestWrapper.getParameterNames();
				while (enu.hasMoreElements()) {
					String paramName = enu.nextElement().trim();
					params.put(paramName, URLDecoder.decode(requestWrapper.getParameter(paramName), "UTF-8"));
				}
				logger.info("sign params:{}", params);
				String sign = SignUtil.sign(params);
				//比较签名
				if (sign.equals(paramSign)) {
					logger.info("sign success!");
				} else {
					logger.error("sign failed! paramSign:{},sign:{}", paramSign, sign);
					httpServletResponse.setStatus(SIGN_FAILED);
					return;
				}
			}
			chain.doFilter(requestWrapper, response);
		} else {
			chain.doFilter(request, response);
		}
	}

	//校验是否为重放请求，是重放返回true，不是返回false
	private boolean checkReplay(HttpServletResponse response, String timestamp, String nonce) {
		// 计算时间差
		long requestTime = Long.parseLong(timestamp);
		long currentTime = System.currentTimeMillis();
		long toleranceTime = currentTime - requestTime;
		// 如果请求时间大于当前时间或者小于最小容忍请求时间, 判定为超时
		if (requestTime > currentTime || apiSecurityConfig.getTimeOut() < toleranceTime) {
			logger.error("Timestamp validation failed! requestTime:{}, currentTime:{},timeOut:{}", requestTime,
					currentTime, apiSecurityConfig.getTimeOut());
			response.setStatus(ILLEGAL_TIMESTAMP);
			return true;
		}
		//如果timestamp和已存在,说明timeout时间内同样的报文之前请求过
		Boolean success = redisTemplate.opsForValue()
				.setIfAbsent(String.format(REDIS_KEY, timestamp, nonce), "", apiSecurityConfig.getTimeOut(),
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
