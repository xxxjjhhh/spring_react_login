package org.example.backend.domain.user.dto;

public record UserResponseDTO(String username, Boolean social, String nickname, String email) {
}
