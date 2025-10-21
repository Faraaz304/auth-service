// package com.example.auth_service.config;

// import lombok.RequiredArgsConstructor;
// import org.springframework.context.annotation.Bean;
// import org.springframework.context.annotation.Configuration;
// import org.springframework.security.authentication.*;
// import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
// import org.springframework.security.config.annotation.web.builders.HttpSecurity;
// import org.springframework.security.config.http.SessionCreationPolicy;
// import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
// import org.springframework.security.crypto.password.PasswordEncoder;
// import org.springframework.security.web.*;
// import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
// import org.springframework.security.authentication.dao.DaoAuthenticationProvider;

// @Configuration
// @RequiredArgsConstructor
// public class SecurityConfig {

//   private final JwtAuthenticationFilter jwtAuthenticationFilter;
//   private final CustomUserDetailsService userDetailsService;

//   @Bean
//   public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//     http
//         .csrf(csrf -> csrf.disable())
//         .authorizeHttpRequests(auth -> auth
//             .requestMatchers("/auth/**").permitAll()
//             .anyRequest().authenticated())
//         .sessionManagement(sess -> sess.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
//         .authenticationProvider(daoAuthProvider())
//         .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

//     return http.build();
//   }

//   @Bean
//   public AuthenticationProvider daoAuthProvider() {
//     DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
//     provider.setPasswordEncoder(passwordEncoder());
//     provider.setUserDetailsService(userDetailsService);
//     return provider;
//   }

//   // Expose AuthenticationManager to be injected into your controller/service for
//   // manual authentication
//   @Bean
//   public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
//     return config.getAuthenticationManager();
//   }

//   @Bean
//   public PasswordEncoder passwordEncoder() {
//     return new BCryptPasswordEncoder();
//   }
// }

package com.example.auth_service.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.*;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.*;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;

@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final CustomUserDetailsService userDetailsService;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth
                        // Public endpoints - only login and register
                        .requestMatchers("/api/auth/login", "/api/auth/register").permitAll()
                        // Swagger UI (optional, if you have it)
                        .requestMatchers("/v3/api-docs/**", "/swagger-ui/**").permitAll()
                        // All other endpoints require authentication
                        .anyRequest().authenticated())
                // Stateless session (for JWT)
                .sessionManagement(sess -> sess.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                // Authentication provider (DAO + BCrypt)
                .authenticationProvider(daoAuthProvider())
                // JWT filter before username/password filter
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public AuthenticationProvider daoAuthProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(passwordEncoder());
        provider.setUserDetailsService(userDetailsService);
        return provider;
    }

    // Expose AuthenticationManager for manual authentication in your
    // service/controller
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}

// package com.example.auth_service.config;

// import lombok.RequiredArgsConstructor;
// import org.springframework.context.annotation.Bean;
// import org.springframework.context.annotation.Configuration;
// import org.springframework.security.authentication.AuthenticationManager;
// import org.springframework.security.authentication.AuthenticationProvider;
// import
// org.springframework.security.authentication.dao.DaoAuthenticationProvider;
// import
// org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
// import
// org.springframework.security.config.annotation.web.builders.HttpSecurity;
// import org.springframework.security.config.http.SessionCreationPolicy;
// import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
// import org.springframework.security.crypto.password.PasswordEncoder;
// import org.springframework.security.web.SecurityFilterChain;
// import
// org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

// @Configuration
// @RequiredArgsConstructor
// public class SecurityConfig {

// private final JwtAuthenticationFilter jwtAuthenticationFilter;
// private final CustomUserDetailsService userDetailsService;

// @Bean
// public SecurityFilterChain securityFilterChain(HttpSecurity http) throws
// Exception {
// http
// .csrf(csrf -> csrf.disable())
// .cors(cors -> cors.disable())
// .authorizeHttpRequests(auth -> auth
// // Permit all requests to authentication endpoints
// .requestMatchers("/api/auth/**").permitAll()
// // Allow actuator endpoints (if any)
// .requestMatchers("/actuator/**").permitAll()
// // All other requests require authentication
// .anyRequest().authenticated()
// )
// .sessionManagement(sess ->
// sess.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
// .authenticationProvider(daoAuthProvider())
// .addFilterBefore(jwtAuthenticationFilter,
// UsernamePasswordAuthenticationFilter.class);

// return http.build();
// }

// @Bean
// public AuthenticationProvider daoAuthProvider() {
// DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
// provider.setPasswordEncoder(passwordEncoder());
// provider.setUserDetailsService(userDetailsService);
// return provider;
// }

// // Expose AuthenticationManager to be injected into your controllers/services
// @Bean
// public AuthenticationManager
// authenticationManager(AuthenticationConfiguration config) throws Exception {
// return config.getAuthenticationManager();
// }

// @Bean
// public PasswordEncoder passwordEncoder() {
// return new BCryptPasswordEncoder();
// }
// }
