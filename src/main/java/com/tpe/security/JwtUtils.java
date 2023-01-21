package com.tpe.security;

import com.tpe.security.service.UserDetailsImpl;
import io.jsonwebtoken.*;

import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import javax.persistence.Column;
import java.util.Date;

@Component
public class JwtUtils {

    private String jwtSecret ="sBoot";

    private long jwtExpirationMs =86400000L;


    // !!! ************ GENERATE TOKEN *****************
    public String generateToken(Authentication authentication) {
        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

        return Jwts.builder().
                setSubject(userDetails.getUsername()).
                setIssuedAt(new Date()).
                setExpiration(new Date(new Date().getTime() + jwtExpirationMs)).
                signWith(SignatureAlgorithm.HS512, jwtSecret).
                compact();
    }
    // !!! ****************** VALIDATE TOKEN ***************************
    public boolean validateToken(String token){

        try {
            Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token);
            return true;
        } catch (ExpiredJwtException e) {
            e.printStackTrace();
        } catch (UnsupportedJwtException e) {
            e.printStackTrace();
        } catch (MalformedJwtException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        } catch (IllegalArgumentException e) {
            e.printStackTrace();
        }
        return false ;
    }

}
