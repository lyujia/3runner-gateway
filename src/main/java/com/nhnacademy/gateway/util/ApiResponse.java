package com.nhnacademy.gateway.util;

import org.springframework.http.HttpStatus;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class ApiResponse<T> {
	private Header header;

	private Body<T> body;

	public ApiResponse(Header header, Body<T> body) {
		this.header = header;
		this.body = body;
	}

	public ApiResponse(Header header) {
		this.header = header;
	}

	@Setter
	@Getter
	@AllArgsConstructor
	public static class Header {
		private boolean isSuccessful;
		private int resultCode;
	}

	@Setter
	@Getter
	public static class Body<T> {
		private T data;

		@JsonCreator
		public Body(@JsonProperty("data") T data) {
			this.data = data;
		}
	}

	public static <T> ApiResponse<T> success(T data) {
		return new ApiResponse<>(
			new Header(true, HttpStatus.OK.value()),
			new Body<>(data)
		);
	}

	public static <T> ApiResponse<T> createSuccess(T data) {
		return new ApiResponse<>(
			new Header(true, HttpStatus.CREATED.value()),
			new Body<>(data)
		);
	}

	public static <T> ApiResponse<T> deleteSuccess(T data) {
		return new ApiResponse<>(
			new Header(false, HttpStatus.NO_CONTENT.value()),
			new Body<>(data)
		);
	}

	public static <T> ApiResponse<T> fail(int errorCode, Body<T> body) {
		return new ApiResponse<>(
			new Header(false, errorCode), body
		);
	}

	public static <T> ApiResponse<T> notFoundFail(Body<T> body) {
		return new ApiResponse<>(
			new Header(false, HttpStatus.NOT_FOUND.value()), body
		);
	}

	public static <T> ApiResponse<T> badRequestFail(Body<T> body) {
		return new ApiResponse<>(
			new Header(false, HttpStatus.BAD_REQUEST.value()), body
		);
	}

	public static <T> ApiResponse<T> forbiddenFail(Body<T> body) {
		return new ApiResponse<>(
			new Header(false, HttpStatus.FORBIDDEN.value()), body
		);
	}

	public static <T> ApiResponse<T> serverErrorFail(Body<T> body) {
		return new ApiResponse<>(
			new Header(false, HttpStatus.INTERNAL_SERVER_ERROR.value()), body
		);
	}

}