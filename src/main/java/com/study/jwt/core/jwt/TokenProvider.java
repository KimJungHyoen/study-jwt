package com.study.jwt.core.jwt;

import com.study.jwt.app.authority.constants.Authority;
import com.study.jwt.app.user.entity.User;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.security.Key;
import java.time.Duration;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

@Slf4j
@Component
public class TokenProvider {
    private final Key key;
    private final int accessTokenDueHour;
    private final int refreshTokenDueDay;
    private final static String AUTHORITIES_KEY = "auth";

    public TokenProvider(@Value("${jwt.secret}") String secret,
                         @Value("${jwt.access-due-hour}") int accessTokenDueHour,
                         @Value("${jwt.refresh-due-day}") int refreshTokenDueDay) {

        byte[] keyBytes = Decoders.BASE64.decode(secret);
        this.key = Keys.hmacShaKeyFor(keyBytes);
        this.accessTokenDueHour = accessTokenDueHour;
        this.refreshTokenDueDay = refreshTokenDueDay;
    }

    public String createAccessToken(Authentication authentication) {

        Claims claims = getAccessTokenClaims(authentication);

        return Jwts.builder()
                .setHeaderParam(Header.TYPE, Header.JWT_TYPE)
                .setClaims(claims)
                .signWith(key, SignatureAlgorithm.HS512)
                .compact();
    }

    public String createRefreshToken(String userId) {

        // 토큰의 expire 시간을 설정
        Date now = new Date();
        Date expiration = new Date(now.getTime() + Duration.ofDays(refreshTokenDueDay).toMillis());

        // Refresh Token 생성
        return Jwts.builder()
                .setHeaderParam(Header.TYPE, Header.JWT_TYPE)
                .setSubject(userId)
                .setIssuedAt(now)
                .setExpiration(expiration)
                .signWith(key, SignatureAlgorithm.HS512)
                .compact();
    }

    public Authentication getAuthentication(String jwtToken) {
        Claims claims = parseClaimsFromJwt(jwtToken);

        Collection<? extends GrantedAuthority> authorities =
                Arrays.stream(claims.get(AUTHORITIES_KEY).toString().split(","))
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());


        User principal = User.builder()
                .userId(claims.getSubject())
                .authority(Authority.valueOf(claims.get(AUTHORITIES_KEY).toString()))
                .build();

        return new UsernamePasswordAuthenticationToken(principal, jwtToken, authorities);
    }

    public Claims parseClaimsFromJwt(String jwtToken) {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(jwtToken)
                .getBody();
    }

    public String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader(HttpHeaders.AUTHORIZATION);

        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.split(" ")[1].trim();
        }

        return null;
    }

    public String getSignature(String token) {
        return token.split("\\.")[2];
    }

    // 토큰의 유효성 검증을 수행
    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
            return true;
        } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) {

            log.info("잘못된 JWT 서명입니다.");
        } catch (ExpiredJwtException e) {

            log.info("만료된 JWT 토큰입니다.");
        } catch (UnsupportedJwtException e) {

            log.info("지원되지 않는 JWT 토큰입니다.");
        } catch (IllegalArgumentException e) {

            log.info("JWT 토큰이 잘못되었습니다.");
        }
        return false;
    }

    private Claims getAccessTokenClaims(Authentication authentication) {
        String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        // 토큰의 expire 시간을 설정
        Date now = new Date();
        Date expiration = new Date(now.getTime() + Duration.ofHours(accessTokenDueHour).toMillis());

        Claims claims = Jwts.claims()
                .setSubject(authentication.getName())
                .setIssuedAt(now)
                .setExpiration(expiration);

        claims.put(AUTHORITIES_KEY, authorities);

        return claims;
    }
}
