package org.zerock.api01.security.filter;

import com.google.gson.Gson;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.MediaType;
import org.springframework.web.filter.OncePerRequestFilter;
import org.zerock.api01.security.exception.RefreshTokenException;
import org.zerock.api01.util.JWTUtil;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.time.Instant;
import java.util.Date;
import java.util.Map;

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
        // 검증...
        // JSON 형식으로 전송된 accessToken과 refreshToken을 받기
        Map<String, String> tokens = parseRequestJSON(request);

        String accessToken = tokens.get("accessToken");
        String refreshToken = tokens.get("refreshToken");

        log.info("accessToken : " + accessToken);
        log.info("refreshToken : " + refreshToken);

        try {
            checkAccessToken(accessToken);   // accessToken 만료시에는 RefreshTokenException이 전달되지 않아요...
        }catch (RefreshTokenException refreshTokenException) {
            refreshTokenException.sendResponseError(response);
            return; // 더 이상 실행X
        }

        Map<String, Object> refreshClaims = null;

        try {
            refreshClaims = checkRefreshToken(refreshToken);
            log.info(refreshClaims);

            // 새로운 Access Token 발행...
            // 1. 여기까지 진행되면 무조건 AccessToken 발행...
            // 2. refreshToken의 만료 일이 얼마 남지 않은 경우 새로 발행...

            // Refresh  Token의 유효시간이 얼마 남지 않은 경우...
            Long exp = (Long) refreshClaims.get("exp");

            Date expTime = new Date(Instant.ofEpochMilli(exp).toEpochMilli() * 1000);
            Date current = new Date(System.currentTimeMillis());

            //만료 시간과 현재 시간의 간격을 계산...
            // 만일 3일 미만인 경우에는 refresh Token도 다시 발행...
            long gapTime = (expTime.getTime() - current.getTime());
            log.info("-----------------------------------------------");
            log.info("current : "+ current);
            log.info("expTime : "+ expTime);
            log.info("gap : "+ gapTime);

            String mid = (String) refreshClaims.get("mid");

            // 여기까지 도착하면 무조건 Access Token을  새로 생성...
            String accessTokenValue = jwtUtil.generateToken(Map.of("mid", mid), 1);
            String refreshTokenValue = tokens.get("refreshToken");    // 기존에 있던 refresh 토큰 값...

            // RefreshToken이 3일 미만으로 기간이 남은 경우....
            if(gapTime < (1000 * 60 * 60 * 24 * 3)) {
                log.info("new Refresh Token requried....");
                refreshTokenValue = jwtUtil.generateToken(Map.of("mid", mid), 30);
            }

            log.info("Refresh Token result..............");
            log.info("accessToken : "+ accessTokenValue);
            log.info("refreshToken : " + refreshTokenValue);

            sendTokens(accessTokenValue,refreshTokenValue, response);

        }catch (RefreshTokenException refreshTokenException) {
            refreshTokenException.sendResponseError(response);
            return; // 더 이상 실행X
        }




    }

    private Map<String, String> parseRequestJSON(HttpServletRequest request) {
        // JSON 데이터를 분석해서 mid, mpw 전달 값을 Map으로 처리...
        try(Reader reader = new InputStreamReader(request.getInputStream())) {
            Gson gson = new Gson();
            return gson.fromJson(reader, Map.class);
        }catch (Exception e) {
            log.error(e.getMessage());
        }
        return null;

    }

    // AccessToken 검증 처리...
    private void checkAccessToken(String accessToken) throws RefreshTokenException {
        try {
            jwtUtil.validateToken(accessToken);  // 토큰 검증...
        }catch (ExpiredJwtException expiredJwtException) {
            log.info("Access Token has expired");
        }catch (Exception e) {
            // Access 토큰 만료 이외의 예외에 대한 RefreshToken 예외 처리...
            throw new RefreshTokenException(RefreshTokenException.ErrorCase.NO_ACCESS);
        }
    }

    private Map<String, Object> checkRefreshToken(String refreshToken) throws RefreshTokenException {
        try {
            Map<String, Object> values =  jwtUtil.validateToken(refreshToken);  // 토큰 검증...
            return values;
        }catch (ExpiredJwtException expiredJwtException) {
            throw new RefreshTokenException(RefreshTokenException.ErrorCase.OLD_REFRESH);
        }catch (MalformedJwtException malformedJwtException) {
            log.error("MalformedJwtException---------------------------------");
            throw new RefreshTokenException(RefreshTokenException.ErrorCase.NO_REFRESH);
        }catch (Exception exception) {
            new RefreshTokenException(RefreshTokenException.ErrorCase.NO_REFRESH);
        }
        return null;
    }

    private void sendTokens(String accessTokenValue, String refreshTokenValue, HttpServletResponse response) {
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        Gson gson = new Gson();
        String jsonStr = gson.toJson(Map.of("accessToken",accessTokenValue, "refreshToken",refreshTokenValue));
        try {
            response.getWriter().println(jsonStr);
        }catch (IOException e) {
            throw new RuntimeException(e);
        }

    }
}
