package com.ropro.learn_spring_security.jwt;

import java.time.Instant;
import java.util.stream.Collectors;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.web.bind.annotation.PostMapping;

// @RestController // Marks this class as a REST controller for handling HTTP requests
public class JwtAuthenticationResource {
    private JwtEncoder jwtEncoder; // Used to encode JWT tokens

    // Constructor to initialize the JwtEncoder dependency
    public JwtAuthenticationResource(JwtEncoder jwtEncoder) {
        this.jwtEncoder = jwtEncoder;
    }

    @PostMapping("/authenticate") // Maps HTTP POST requests to /authenticate
    public JwtRespose authenticate(Authentication authentication) {
        // Calls the createToken method and wraps the result in a JwtRespose record
        return new JwtRespose(createToken(authentication));
    }

    private String createToken(Authentication authentication) {
        // Constructs JWT claims, including issuer, issued time, expiry, subject, and
        // scope
        var claims = JwtClaimsSet.builder()
                .issuer("self") // The entity that issued the token
                .issuedAt(Instant.now()) // Current timestamp as the issued time
                .expiresAt(Instant.now().plusSeconds(60 * 30)) // Token validity period (30 minutes)
                .subject(authentication.getName()) // Sets the username as the subject
                .claim("scope", createScope(authentication)) // Adds custom claims for scope
                .build();
        // Encodes the claims into a JWT token and returns its string value
        return jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
    }

    private String createScope(Authentication authentication) {
        // Extracts the authorities (roles/permissions) from the authentication object
        // and concatenates them into a space-separated string
        return authentication.getAuthorities().stream()
                .map(a -> a.getAuthority()) // Converts each authority to its string representation
                .collect(Collectors.joining(" ")); // Joins all authorities with a space
    }

}

// Record class to represent the JWT response containing only the token
record JwtRespose(String token) {
}
