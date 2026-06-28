package com.backend.devsecopsplatform_backend.configuration;

import com.backend.devsecopsplatform_backend.service.CustomUserDetailsService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.http.HttpMethod;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import java.util.Arrays;
import java.util.List;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    private final CustomUserDetailsService customUserDetailsService;
    private final JwtUtils jwtUtils;
    private final SecurityExceptionHandlers securityExceptionHandlers;
    private final SecurityMonitoringFilter securityMonitoringFilter;
    private final TwoFactorEnforcementFilter twoFactorEnforcementFilter;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(HttpSecurity http, PasswordEncoder passwordEncoder) throws Exception {
        AuthenticationManagerBuilder authenticationManagerBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);
        authenticationManagerBuilder.userDetailsService(customUserDetailsService).passwordEncoder(passwordEncoder);
        return authenticationManagerBuilder.build();
    }

    @Bean
    public CorsFilter corsFilter() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration();

        config.setAllowCredentials(true);
        config.setAllowedOrigins(List.of(
                "http://localhost:4200",
                "http://envirotest.local:4200",
                "http://envirotest.local"
        ));
        config.setAllowedHeaders(List.of("*"));
        config.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
        config.setMaxAge(3600L);

        source.registerCorsConfiguration("/**", config);
        return new CorsFilter(source);
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, JwtFilter jwtFilter) throws Exception {
        http
                .cors(cors -> cors.configure(http))
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint(securityExceptionHandlers)
                        .accessDeniedHandler(securityExceptionHandlers)
                )
                .authorizeHttpRequests(auth -> auth
                        // CORS preflight (OPTIONS) doit toujours passer
                        .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                        // Endpoint error Spring (évite 401 sur /error en cas d'exception 500)
                        .requestMatchers("/error", "/projet/error").permitAll()
                        .requestMatchers("/auth/**", "/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html").permitAll()
                        .requestMatchers("/projet/auth/**", "/projet/v3/api-docs/**", "/projet/swagger-ui/**", "/projet/swagger-ui.html").permitAll()
                        // Déploiement : nécessite un JWT (on a besoin du user courant en service)
                        .requestMatchers("/api/deploy/**", "/projet/api/deploy/**").authenticated()
                        // API pipelines (détail, logs, scans) : accès avec ou sans JWT (contrôle métier dans le controller)
                        .requestMatchers("/api/pipelines/**", "/projet/api/pipelines/**").authenticated()
                        // API SonarQube (résultats, hotspots, duplications, transition/assign issues) : authentifié
                        .requestMatchers("/api/sonarqube/**", "/projet/api/sonarqube/**").authenticated()
                        // API IA (analyse d'artifacts : vulnérabilités + remédiations)
                        .requestMatchers("/api/ai/**", "/projet/api/ai/**").authenticated()
                        // API Findings (dashboard vulnérabilités centralisé)
                        .requestMatchers("/api/findings/**", "/projet/api/findings/**").authenticated()
                        // API DefectDojo (dashboard sécurité par produit / branche)
                        .requestMatchers("/api/defectdojo/**", "/projet/api/defectdojo/**").authenticated()
                        // Snapshot pipeline CI (secret partagé, sans JWT)
                        .requestMatchers(HttpMethod.POST,
                                "/api/quality-gate/internal/snapshot",
                                "/projet/api/quality-gate/internal/snapshot").permitAll()
                        // Quality Gate (recommandation de déploiement par branche)
                        .requestMatchers("/api/quality-gate/**", "/projet/api/quality-gate/**").authenticated()
                        // API Reports (PDF export)
                        .requestMatchers("/api/reports/**", "/projet/api/reports/**").authenticated()
                        // Webhook GitLab (appelé par GitLab, pas par le front)
                        .requestMatchers("/api/webhooks/**", "/projet/api/webhooks/**").permitAll()
                        // Administration : réservé aux admins authentifiés
                        .requestMatchers("/api/admin/**", "/projet/api/admin/**").hasAuthority("ROLE_ADMIN")
                        // Reste de l'API : nécessite un JWT valide
                        .anyRequest().authenticated()
                )
                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterAfter(twoFactorEnforcementFilter, JwtFilter.class)
                .addFilterBefore(securityMonitoringFilter, JwtFilter.class);

        return http.build();
    }
}