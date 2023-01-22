package com.tpe.security;

import com.tpe.security.service.*;
import io.jsonwebtoken.*;
import org.springframework.security.core.*;
import org.springframework.stereotype.*;

import java.util.*;

@Component
public class JwtUtils {
    // 1 : JWT generate
    // 2: JWT valide
    // 3 : JWT --> userName
    private String jwtSecret = "sboot";

    private  long jwtExpirationMs = 86400000;   // 24*60*60*1000

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

    // !!! ********** JWT tokenden userName'i alalım ************
    public String getUserNameFromJwtToken(String token) {
        return Jwts.parser().
                setSigningKey(jwtSecret).
                parseClaimsJws(token).
                getBody().
                getSubject();
    }

}
