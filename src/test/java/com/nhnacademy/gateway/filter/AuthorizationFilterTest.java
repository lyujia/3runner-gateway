package com.nhnacademy.gateway.filter;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.util.Arrays;
import java.util.Objects;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.data.redis.core.HashOperations;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ServerWebExchange;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nhnacademy.gateway.util.TokenDetails;
import com.nhnacademy.gateway.jwt.JWTUtil;

import reactor.core.publisher.Mono;

/**
 * Authorization filter 테스트 입니다.
 *
 * @author 오연수
 */
@SpringBootTest
@ExtendWith(MockitoExtension.class)
public class AuthorizationFilterTest {
	@Mock
	private JWTUtil jwtUtil;

	@Mock
	private GatewayFilterChain chain;

	@Mock
	private RedisTemplate<String, Object> redisTemplate;

	@Mock
	private HashOperations<String, String, String> hashOperations;

	@Mock
	private ObjectMapper objectMapper;

	@InjectMocks
	private AuthorizationFilter filter;


	@BeforeEach
	public void setup() {

		filter = new AuthorizationFilter(jwtUtil, redisTemplate, objectMapper);
	}

	@DisplayName("Jwt가 유효한 경우 테스트")
	@Test
	public void testFilter_ValidJwt() throws JsonProcessingException {
		// given
		String validToken = "valid_token";
		Long memberId = 12345L;
		String uuid = "uuid_test";
		TokenDetails tokenDetails = new TokenDetails("email@naver.com", Arrays.asList("ROLE_USER"), memberId);

		ServerWebExchange exchange = MockServerWebExchange.from(
			MockServerHttpRequest.get("/api/test")
				.header(HttpHeaders.AUTHORIZATION, "Bearer " + validToken)
				.build()
		);

		when(jwtUtil.isExpired(validToken)).thenReturn(false);
		when(jwtUtil.getUuid(validToken)).thenReturn(uuid);
		String data = "{\"email\":\"email@naver.com\",\"auths\":[\"ROLE_USER\"],\"memberId\":12345}";
		doReturn(hashOperations).when(redisTemplate).opsForHash();
		doReturn(tokenDetails).when(objectMapper).readValue(data, TokenDetails.class);
		when(redisTemplate.opsForHash().get("token_details", uuid)).thenReturn(data);

		when(chain.filter(any(ServerWebExchange.class))).thenReturn(Mono.empty());

		// when
		Mono<Void> result = filter.apply(new AuthorizationFilter.Config(jwtUtil)).filter(exchange, chain);

		// then
		ServerHttpRequest modifiedRequest = exchange.getRequest();
		assertEquals(String.valueOf(memberId), modifiedRequest.getHeaders().getFirst("Member-Id"));
		verify(chain, times(1)).filter(any(ServerWebExchange.class));
	}
}
