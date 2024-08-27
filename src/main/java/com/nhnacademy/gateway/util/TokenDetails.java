package com.nhnacademy.gateway.util;

import java.io.Serializable;
import java.util.List;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

@AllArgsConstructor
@NoArgsConstructor
@Getter
public class TokenDetails implements Serializable {
	private String email;
	private List<String> auths;
	private Long memberId;
}
