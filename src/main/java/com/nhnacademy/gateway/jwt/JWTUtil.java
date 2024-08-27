package com.nhnacademy.gateway.jwt;

import java.nio.charset.StandardCharsets;
import java.util.Date;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;

/**
 * JWT Utility Class
 *
 * @author 오연수
 */
@Component
public class JWTUtil {
	private SecretKey secretKey;

	public JWTUtil(@Value("${spring.jwt.secret}") String secret) {
		// 양방향 암호화 알고리즘 사용
		this.secretKey = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8),
			Jwts.SIG.HS256.key().build().getAlgorithm());
	}

	/**
	 * JWT 에서 멤버의 uuid 를 가져온다.
	 *
	 * @param token 토큰
	 * @return the uuid
	 */
	public String getUuid(String token) {
		return Jwts.parser()
			.verifyWith(secretKey)
			.build()
			.parseSignedClaims(token)
			.getPayload()
			.get("uuid", String.class);
	}

	/**
	 * JWT 에서 토큰의 종류를 가져온다.
	 *
	 * @param token 토큰
	 * @return the category
	 */
	public String getCategory(String token) {
		return Jwts.parser()
			.verifyWith(secretKey)
			.build()
			.parseSignedClaims(token)
			.getPayload()
			.get("category", String.class);
	}

	/**
	 * JWT 유효 기간(만료 기간) 체크한다.
	 *
	 * @param token access token
	 * @return 유효성
	 */
	public Boolean isExpired(String token) throws ExpiredJwtException {
		try {
			Date expiration = Jwts.parser()
				.verifyWith(secretKey)
				.build()
				.parseSignedClaims(token)
				.getPayload()
				.getExpiration();
			return expiration.before(new Date());
		} catch (ExpiredJwtException e) {
			return true;
		}
	}
}
