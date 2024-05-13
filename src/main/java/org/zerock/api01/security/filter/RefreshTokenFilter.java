package org.zerock.api01.security.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.web.filter.OncePerRequestFilter;
import org.zerock.api01.util.JWTUtil;

import java.io.IOException;

@Log4j2
@RequiredArgsConstructor
public class RefreshTokenFilter extends OncePerRequestFilter {

    private final String refreshPath;
    private final JWTUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String path = request.getRequestURI();
        if (!path.equals(refreshPath)) {   // refreshPath가 아닌 경우에는 스킵
            log.info("skip refresh token filter..... ");
            filterChain.doFilter(request,response);
            return;
        }

        log.info("Refresh Token Filter ... run ............... 1");

    }
}
