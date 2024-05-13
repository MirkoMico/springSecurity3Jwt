package com.spring.securityLoginJwt.service;

import com.spring.securityLoginJwt.model.User;
import com.spring.securityLoginJwt.repository.TokenRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.function.Function;

@Service
public class JwtService {
    private String SECRET_KEY="87eaa0fefe84487b132e21be368b7d3a592f43de3db5b38bc9da3faf27a65ed2";
    @Autowired
    private TokenRepository tokenRepository;

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

  /*  public boolean isValid (String token, UserDetails user) {
         String username = extractUsername(token);

        boolean validToken = tokenRepository
                .findByToken(token)
                .map(t -> !t.isLoggedOut())
                .orElse(false);

        return (username.equals(user.getUsername())) && !isTokenExpired(token) && validToken;
    }*/
  public boolean isValid(String token, UserDetails user) {
      String username = extractUsername(token);

      boolean validToken = tokenRepository
              .findByToken(token)
              .map(t -> {
                  if (t.isLoggedOut()) {
                      // Se il token è già stato contrassegnato come logout, restituisci false direttamente
                      return false;
                  } else {
                      // Altrimenti, controlla se il token è ancora valido
                      boolean isValid = !isTokenExpired(token);
                      if (!isValid) {
                          // Se il token non è più valido, imposta il flag isLoggedOut a true e aggiorna il token nel database
                          t.setLoggedOut(true);
                          tokenRepository.save(t);
                      }
                      return isValid;
                  }
              })
              .orElse(false);

      return (username.equals(user.getUsername())) && validToken;
  }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }
    public  <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {

         Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }
    private Claims extractAllClaims(String token) {
        return Jwts
                .parser()
                .verifyWith(getSigninKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
    public String generateToken(User user) {
        String token = Jwts
                .builder()
                .subject(user.getUsername())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + 24 * 60 * 60 *1000))
                .signWith(getSigninKey())
                .compact();
        return token;

    }
    private SecretKey getSigninKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
