package com.nhnacademy.gateway.util;

import lombok.Builder;

@Builder
public record ErrorResponseForm(String title, int status, String timestamp) {
}

