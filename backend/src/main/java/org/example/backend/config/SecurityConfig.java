package org.example.backend.config;

import jakarta.servlet.http.HttpServletResponse;
import org.example.backend.domain.jwt.service.JwtService;
import org.example.backend.filter.JWTFilter;
import org.example.backend.filter.LoginFilter;
import org.example.backend.handler.RefreshTokenLogoutHandler;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final AuthenticationConfiguration authenticationConfiguration;
    private final AuthenticationSuccessHandler loginSuccessHandler;
    private final AuthenticationSuccessHandler socialSuccessHandler;
    private final JwtService jwtService;

    public SecurityConfig(
            AuthenticationConfiguration authenticationConfiguration,
            @Qualifier("LoginSuccessHandler") AuthenticationSuccessHandler loginSuccessHandler,
            @Qualifier("SocialSuccessHandler") AuthenticationSuccessHandler socialSuccessHandler,
            JwtService jwtService
    ) {
        this.authenticationConfiguration = authenticationConfiguration;
        this.loginSuccessHandler = loginSuccessHandler;
        this.socialSuccessHandler = socialSuccessHandler;
        this.jwtService = jwtService;
    }

    // 커스텀 자체 로그인 필터를 위한 AuthenticationManager Bean 수동 등록
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    // 권한 계층
    @Bean
    public RoleHierarchy roleHierarchy() {
        return RoleHierarchyImpl.withRolePrefix("ROLE_")
                .role(UserRoleType.ADMIN.name()).implies(UserRoleType.USER.name())
                .build();
    }

    // 비밀번호 단방향(BCrypt) 암호화용 Bean
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // CORS Bean
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(List.of("http://localhost:5173"));
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(List.of("*"));
        configuration.setAllowCredentials(true);
        configuration.setExposedHeaders(List.of("Authorization", "Set-Cookie"));
        configuration.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    // SecurityFilterChain
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        // CSRF 보안 필터 disable
        http
                .csrf(AbstractHttpConfigurer::disable);

        // CORS 설정
        http
                .cors(cors -> cors.configurationSource(corsConfigurationSource()));

        // 기본 로그아웃 필터 + 커스텀 Refresh 토큰 삭제 핸들러 추가
        http
                .logout(logout -> logout
                        .addLogoutHandler(new RefreshTokenLogoutHandler(jwtService)));

        // 기본 Form 기반 인증 필터들 disable
        http
                .formLogin(AbstractHttpConfigurer::disable);

        // 기본 Basic 인증 필터 disable
        http
                .httpBasic(AbstractHttpConfigurer::disable);

        // OAuth2 인증용
        http
                .oauth2Login(oauth2 -> oauth2
                        .successHandler(socialSuccessHandler));

        // 인가
        http
                .authorizeHttpRequests(auth -> auth
                        .anyRequest().permitAll());

        // 예외 처리
        http
                .exceptionHandling(e -> e
                        .authenticationEntryPoint((request, response, authException) -> {
                            response.sendError(HttpServletResponse.SC_UNAUTHORIZED); // 401 응답
                        })
                        .accessDeniedHandler((request, response, authException) -> {
                            response.sendError(HttpServletResponse.SC_FORBIDDEN); // 403 응답
                        })
                );

        // 커스텀 필터 추가
        http
                .addFilterBefore(new JWTFilter(), LogoutFilter.class);
        http
                .addFilterBefore(new LoginFilter(authenticationManager(authenticationConfiguration), loginSuccessHandler), UsernamePasswordAuthenticationFilter.class);

        // 세션 필터 설정 (STATELESS)
        http
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        return http.build();
    }

}
