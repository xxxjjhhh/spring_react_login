package org.example.backend.domain.jwt.dto;

public record JWTResponseDTO(String accessToken, String refreshToken) {
}
