package org.zerock.api01.security.filter;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.web.filter.OncePerRequestFilter;
import org.zerock.api01.security.exception.AccessTokenException;
import org.zerock.api01.util.JWTUtil;

import java.io.IOException;
import java.util.Map;

@Log4j2
@RequiredArgsConstructor
public class TokenCheckFilter extends OncePerRequestFilter {

    private final JWTUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String path = request.getRequestURI();
        if(!path.startsWith("/api/")) {
            filterChain.doFilter(request, response);
            return;
        }

        log.info("Token Check Filter...............................");
        log.info("JWTUtil : " + jwtUtil);

        try {
            validateAccessToken(request);
            filterChain.doFilter(request, response);
        }catch (AccessTokenException accessTokenException) {
            accessTokenException.sendResponseError(response);
        }

    }

    private Map<String, Object> validateAccessToken(HttpServletRequest request) throws AccessTokenException {
        String headerStr = request.getHeader("Authorization");  // 토큰이 저장될 헤더...

        if (headerStr == null || headerStr.length() < 8) {   // 토큰이 없는 경우....
            throw new AccessTokenException(AccessTokenException.TOKEN_ERROR.UNACCEPT);
        }

        // Bearer 생략....
        String tokenType = headerStr.substring(0, 6);
        String tokenStr = headerStr.substring(7);

        if(tokenType.equalsIgnoreCase("Bearer") == false) {  //잘못된 타입
            throw new AccessTokenException(AccessTokenException.TOKEN_ERROR.BADTYPE);
        }

        try {
            Map<String, Object> values = jwtUtil.validateToken(tokenStr);
            return values;
        }catch (MalformedJwtException malformedJwtException) {
            log.info("MalformedJwtException------------------------------------");
            throw new AccessTokenException(AccessTokenException.TOKEN_ERROR.MALFORM);
        }catch (SignatureException signatureException) {
            log.info("Signature Exception------------------------------------");
            throw new AccessTokenException(AccessTokenException.TOKEN_ERROR.BADSIGN);
        }catch (ExpiredJwtException expiredJwtException) {
            log.info("expiredJwtException-------------------------------------");
            throw new AccessTokenException(AccessTokenException.TOKEN_ERROR.EXPIRED);
        }
    }



}
