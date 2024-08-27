package com.nhnacademy.gateway.filter;

import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nhnacademy.gateway.util.ErrorResponseForm;
import com.nhnacademy.gateway.util.TokenDetails;
import com.nhnacademy.gateway.jwt.JWTUtil;
import com.nhnacademy.gateway.util.ApiResponse;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

/**
 * Front 서버로부터 넘어온 JWT 를 검증한다.
 * 토큰 내의 멤버 아이디 정보를 헤더에 추가해주는 필터.
 *
 * @author 오연수
 */
@Component
@Slf4j
public class AuthorizationFilter extends AbstractGatewayFilterFactory<AuthorizationFilter.Config> {
	private final String TOKEN_DETAILS = "token_details";

	private final RedisTemplate<String, Object> redisTemplate;
	private final JWTUtil jwtUtil;
	private final ObjectMapper objectMapper;

	public AuthorizationFilter(JWTUtil jwtUtil, RedisTemplate<String, Object> redisTemplate, ObjectMapper objectMapper) {
		super(Config.class);
		this.jwtUtil = jwtUtil;
		this.redisTemplate = redisTemplate;
		this.objectMapper = objectMapper;
	}

	@RequiredArgsConstructor
	public static class Config {
		private final JWTUtil jwtUtils;
	}

	@Override
	public GatewayFilter apply(AuthorizationFilter.Config config) {
		return (exchange, chain) -> {
			ServerHttpRequest request = exchange.getRequest();

			// /bookstore/login 은 검증 제외
			if (request.getURI().getPath().startsWith("/bookstore/login")) {
				log.info("bookstore login api 요청");
				return chain.filter(exchange);
			}
			String token;
			if (request.getURI().getPath().startsWith("/bookstore/token")) {

				String requestUrl = request.getURI().getPath();
				String[] requestUrlSplit = requestUrl.split("/");
				token = requestUrlSplit[requestUrlSplit.length - 1];
			} else if (!request.getHeaders().containsKey("Authorization")) {
				log.info("비회원 요청");
				return chain.filter(exchange);
			} else {
				String authorization = request.getHeaders().get(HttpHeaders.AUTHORIZATION).getFirst();
				token = authorization.split(" ")[1];
				if (jwtUtil.isExpired(token)) {
					log.error("JWT is not valid");
					return onError(exchange, "토큰 만료", HttpStatus.UNAUTHORIZED);
				}
			}

			// 넘어가는 요청에 대해 Member-Id Header 추가
			String uuid = jwtUtil.getUuid(token);
			String data = (String)redisTemplate.opsForHash().get(TOKEN_DETAILS, uuid);
			TokenDetails tokenDetails;
			try {
				tokenDetails = objectMapper.readValue(data, TokenDetails.class);
			} catch (JsonProcessingException e) {
				throw new RuntimeException(e);
			}

			if (tokenDetails == null) {
				log.warn("TokenDetails not found in Redis for UUID: {}", uuid);
				return onError(exchange, "토큰 세부 정보 없음", HttpStatus.UNAUTHORIZED);
			} else {
				log.info("TokenDetails retrieved: {}", tokenDetails);
			}

			String userId = String.valueOf(tokenDetails.getMemberId());
			String userAuth = String.valueOf(tokenDetails.getAuths());

			// ServerHttpRequestDecorator를 사용하여 요청을 변조합니다.
			ServerHttpRequest modifiedRequest = request.mutate()
				.header("Member-Id", userId)
				.header("Member-Auth", userAuth)
				.build();

			ServerWebExchange modifiedExchange = exchange.mutate().request(modifiedRequest).build();
			return chain.filter(modifiedExchange);
		};
	}

	private Mono<Void> onError(ServerWebExchange exchange, String err, HttpStatus httpStatus) {
		ServerHttpResponse response = exchange.getResponse();
		response.setStatusCode(httpStatus);
		ApiResponse<ErrorResponseForm> resp = new ApiResponse<>(
			new ApiResponse.Header(false, HttpStatus.UNAUTHORIZED.value()),
			new ApiResponse.Body<>(ErrorResponseForm.builder()
				.title(err)
				.status(httpStatus.value())
				.timestamp(String.valueOf(System.currentTimeMillis()))
				.build()));
		byte[] bytes = new byte[0];
		try {
			bytes = objectMapper.writeValueAsBytes(resp);
		} catch (JsonProcessingException e) {
			log.error("Error writing response body", e);
		}

		DataBuffer buffer = response.bufferFactory().wrap(bytes);
		response.getHeaders().add(HttpHeaders.CONTENT_TYPE, "application/json");

		return response.writeWith(Mono.just(buffer));
	}

}
