package my.project.authentication_api.webToken;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.aspectj.apache.bcel.generic.RET;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;
@Service
public class JjwtService {

    private static final String SECRET = "FFC6CFE6E98214920404524338542671D77E253924B14745C32D2ACBEF7FB9F7ADE99AF8C27A1F21B1F5EF5AE62C58508B792344930E75A7F61A566F9AC97BA6";
    private static final long VALIDITY = TimeUnit.MINUTES.toMillis(30);

    public String generateToken(UserDetails userDetails){
        Map<String,String> claims = new HashMap<>();
        claims.put("iss","https://www.github.com/Plinio-almd");
        return Jwts.builder()
                .claims(claims)
                .subject(userDetails.getUsername())
                .issuedAt(Date.from(Instant.now()))
                .expiration(Date.from(Instant.now().plusMillis(VALIDITY)))
                .signWith(generateKey())
                .compact();
    }

    private SecretKey generateKey(){
        byte[] decodedKey = Base64.getDecoder().decode(SECRET);
        return Keys.hmacShaKeyFor(decodedKey);
    }
    public String extractUsername(String jwt){
        Claims claim = getClaims(jwt);
        return claim.getSubject();
    }

    private Claims getClaims(String jwt) {
        return Jwts.parser()
                .verifyWith(generateKey())
                .build()
                .parseSignedClaims(jwt)
                .getPayload();
    }

    public boolean isTokenValid(String jwt) {
        Claims claim = getClaims(jwt);
        return claim.getExpiration().after(Date.from(Instant.now()));

    }
}
