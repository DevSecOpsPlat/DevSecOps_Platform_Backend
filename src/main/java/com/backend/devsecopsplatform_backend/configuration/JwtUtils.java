package com.backend.devsecopsplatform_backend.configuration;
import com.backend.devsecopsplatform_backend.entity.Role;
import com.backend.devsecopsplatform_backend.service.*;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;


import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

@Component
public class JwtUtils {
   

    @Value("${app.secret-key}")
    private String secretKey;

    @Value("${app.expiration-time}")
    private long expirationTime;

    public String generateToken(String username, List<Role> roles) {
        return Jwts.builder()
                .setSubject(username)
                .claim("roles", roles.stream().map(Role::name).toList())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expirationTime ))
                .signWith(getSignKey(), SignatureAlgorithm.HS256)
                .compact();
    }



    private Key getSignKey() {
        byte[] keyBytes = secretKey.getBytes();
        return new SecretKeySpec(keyBytes, SignatureAlgorithm.HS256.getJcaName());
    }
    public Boolean validateToken(String token,  UserDetails userDetails) {
        String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    private boolean isTokenExpired(String token) {
        return extractExpirationDate(token).before(new Date());
    }
    private Date extractExpirationDate(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    private <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
    final Claims claims= extractAllClaims(token);
    return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
    return  Jwts.parser()
            .setSigningKey(getSignKey())
            .parseClaimsJws(token)
            .getBody();
    }


}