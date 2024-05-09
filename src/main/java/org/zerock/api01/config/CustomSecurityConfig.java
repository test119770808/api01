package org.zerock.api01.config;


import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.zerock.api01.security.APIUserDetailsService;

@Configuration
@Log4j2
@EnableMethodSecurity
@RequiredArgsConstructor
public class CustomSecurityConfig {

    // 주입 - 실제 인증처리를 위한 AuthenticationManager 객체 설정이 필요함....
    private final APIUserDetailsService apiUserDetailsService;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        log.info("------------------------- web configure ------------------------------");

        // 정적 리소스 필터링 제외
        return (web) -> web.ignoring()
                .requestMatchers(
                        PathRequest.toStaticResources().atCommonLocations()
                );
    }

    @Bean
    public SecurityFilterChain filterChain(final HttpSecurity http) throws Exception {
        log.info("------------------------ configure ----------------------------------");

        // AuthenticationManager 설정
        AuthenticationManagerBuilder authenticationManagerBuilder =
                http.getSharedObject(AuthenticationManagerBuilder.class);

        authenticationManagerBuilder
                .userDetailsService(apiUserDetailsService)
                        .passwordEncoder(passwordEncoder());

        // Get AuthenticationManager
        AuthenticationManager authenticationManager = authenticationManagerBuilder.build();

        // 인증 메니저 등록...
        http.authenticationManager(authenticationManager);

        // APILoginFilter 설정....



        // 1. CSRF 토큰의 비활성화
        http.csrf(httpSecurityCsrfConfigurer -> httpSecurityCsrfConfigurer.disable());
        // 2. 세션 사용하지 않아요....
        http.sessionManagement(httpSecuritySessionManagementConfigurer ->
                httpSecuritySessionManagementConfigurer.sessionCreationPolicy(
                        SessionCreationPolicy.STATELESS
                ));

        return http.build();
    }

}
