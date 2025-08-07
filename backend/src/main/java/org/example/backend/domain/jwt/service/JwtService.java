package org.example.backend.domain.jwt.service;

import org.example.backend.domain.jwt.entity.RefreshEntity;
import org.example.backend.domain.jwt.repository.RefreshRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class JwtService {

    private final RefreshRepository refreshRepository;

    public JwtService(RefreshRepository refreshRepository) {
        this.refreshRepository = refreshRepository;
    }

    // 소셜 로그인 성공 후 쿠키(Refresh) -> 헤더 방식으로 응답 <-- 이건 추후에 작성

    // Refresh 토큰으로 Access 토큰 재발급 로직 (Rotate 포함) <-- 이건 추후에 작성

    // JWT Refresh 토큰 발급 후 저장 메소드
    @Transactional
    public void addRefresh(String username, String refreshToken) {
        RefreshEntity entity = RefreshEntity.builder()
                .username(username)
                .refresh(refreshToken)
                .build();

        refreshRepository.save(entity);
    }

    // JWT Refresh 존재 확인 메소드
    @Transactional(readOnly = true)
    public Boolean existsRefresh(String refreshToken) {
        return refreshRepository.existsByRefresh(refreshToken);
    }

    // JWT Refresh 토큰 삭제 메소드
    public void removeRefresh(String refreshToken) {
        refreshRepository.deleteByRefresh(refreshToken);
    }

    // 특정 유저 Refresh 토큰 모두 삭제 (탈퇴)
    public void removeRefreshUser(String username) {
        refreshRepository.deleteByUsername(username);
    }

}
