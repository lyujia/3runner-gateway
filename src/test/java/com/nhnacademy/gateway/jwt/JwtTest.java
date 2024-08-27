package com.nhnacademy.gateway.jwt;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.List;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

/**
 * JWT Utility class 에 대한 테스트입니다.
 *
 * @author 오연수
 */
public class JwtTest {

	private JWTUtil jwtUtil;
	private SecretKey secretKey;

	/**
	 * Sets up.
	 */
	@BeforeEach
	public void setUp() {
		String secret = "my-very-secure-secret-key-111111jdasdlfjqwlefjxlzvmqwefdsfcxmvoiwfjp";
		secretKey = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8),
			SignatureAlgorithm.HS256.getJcaName());
		jwtUtil = new JWTUtil(secret);
	}

	private String createTestToken(String username, String auth, Long memberId, Date expiration) {
		return Jwts.builder()
			.claim("username", username)
			.claim("auth", auth)
			.claim("memberId", memberId)
			.expiration(expiration)
			.signWith(secretKey)
			.compact();
	}

	@DisplayName("토큰에서 유효 기간 검사")
	@Test
	public void testIsExpired() {
		String token1 = createTestToken("testUser", "ROLE_USER", 1L, new Date(System.currentTimeMillis() - 10000));
		assertTrue(jwtUtil.isExpired(token1));
		String token2 = createTestToken("testUser", "ROLE_USER", 1L, new Date(System.currentTimeMillis() + 10000));
		assertFalse(jwtUtil.isExpired(token2));
	}
}
