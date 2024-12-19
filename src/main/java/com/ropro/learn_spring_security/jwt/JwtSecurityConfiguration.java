package com.ropro.learn_spring_security.jwt;

import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import static org.springframework.security.config.Customizer.withDefaults;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

import javax.sql.DataSource;

@Configuration // Marks this class as a configuration for Spring Security
public class JwtSecurityConfiguration {

    @Bean
    @Order(SecurityProperties.BASIC_AUTH_ORDER) // Sets the execution order for the security filter chain
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        // Configures authorization rules to require authentication for all requests
        http.authorizeHttpRequests((requests) -> requests.anyRequest().authenticated());

        // Disables session creation to enforce stateless authentication
        http.sessionManagement((session) -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        // Enables basic authentication
        http.httpBasic(withDefaults());

        // Disables CSRF protection (not recommended for stateful applications)
        http.csrf(csrf -> csrf.disable());

        // Configures HTTP headers to allow frames (useful for H2 database console)
        http.headers(headers -> headers.frameOptions(frameOptions -> frameOptions.disable()));

        // Configures OAuth2 resource server to use JWT for authentication
        http.oauth2ResourceServer(oauth2 -> oauth2.jwt(withDefaults()));

        return http.build(); // Builds the security filter chain
    }

    @Bean
    public DataSource dataSource() {
        // Creates an embedded H2 database and initializes the default user schema
        return new EmbeddedDatabaseBuilder()
                .setType(EmbeddedDatabaseType.H2)
                .addScript(JdbcDaoImpl.DEFAULT_USER_SCHEMA_DDL_LOCATION)
                .build();
    }

    @Bean
    public UserDetailsService userDetailService(DataSource dataSource) {
        // Creates a sample user with the "USER" role
        var user = User.withUsername("joel")
                .password("dummy") // Plain text password for demonstration purposes
                .passwordEncoder(str -> passwordEncoder().encode(str)) // Encodes the password using BCrypt
                .roles("USER") // Assigns the "USER" role
                .build();

        // Creates an admin user with both "ADMIN" and "USER" roles
        var admin = User.withUsername("admin")
                .password("dummy")
                .passwordEncoder(str -> passwordEncoder().encode(str))
                .roles("ADMIN", "USER")
                .build();

        // Initializes a JdbcUserDetailsManager with the data source
        var jdbcUserDetailsManager = new JdbcUserDetailsManager(dataSource);

        jdbcUserDetailsManager.createUser(user); // Adds the user to the database
        jdbcUserDetailsManager.createUser(admin); // Adds the admin to the database

        return jdbcUserDetailsManager; // Returns the user details manager
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(); // Provides password encoding functionality
    }

    @Bean
    public KeyPair keyPair() {
        try {
            // Generates an RSA key pair for signing and verifying JWTs
            var keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            return keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new RuntimeException(ex); // Throws a runtime exception if key pair generation fails
        }
    }

    @Bean
    public RSAKey rsaKey(KeyPair keyPair) {
        // Builds an RSAKey using the public and private keys, and assigns a unique key
        // ID
        return new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                .privateKey(keyPair.getPrivate())
                .keyID(UUID.randomUUID().toString()) // Generates a random key ID
                .build();
    }

    /**
     * Creates a JWKSource bean that provides the JSON Web Key (JWK) set containing
     * the RSA key.
     *
     * @param rsaKey the RSA key to be included in the JWK set
     * @return a JWKSource that can be used to select JWKs from the JWK set
     */
    @Bean
    public JWKSource<SecurityContext> jwtSource(RSAKey rsaKey) {
        var jwkSet = new JWKSet(rsaKey); // Creates a JWKSet containing the RSAKey
        // Returns a JWKSource that selects keys from the JWKSet
        return (jwkSelector, context) -> jwkSelector.select(jwkSet);
    }

    @Bean
    public JwtDecoder jwtDecoder(RSAKey rsaKey) throws JOSEException {
        // Configures a JWT decoder to verify tokens using the RSA public key
        return NimbusJwtDecoder
                .withPublicKey(rsaKey.toRSAPublicKey())
                .build();
    }

    @Bean
    public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwtSource) {
        // Configures a JWT encoder to create tokens using the JWKSource
        return new NimbusJwtEncoder(jwtSource);
    }

}
