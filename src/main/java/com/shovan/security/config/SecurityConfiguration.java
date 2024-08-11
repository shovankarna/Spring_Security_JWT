package com.shovan.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfiguration {
        private final JwtAuthenticationFilter jwtAuthenticationFilter;
        private final AuthenticationProvider authenticationProvider;

        @Bean
        public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
                http
                                .csrf(csrf -> csrf.disable())
                                .authorizeHttpRequests(authz -> authz
                                                .requestMatchers("/api/v1/auth/**", "/login", "/oauth2/**").permitAll()
                                                .requestMatchers("/css/**", "/js/**", "/images/**").permitAll()
                                                .requestMatchers("/api/v1/secure/auth/**").authenticated()
                                                .requestMatchers("/api/v1/admin/**").hasAuthority("ROLE_ADMIN")
                                                .anyRequest().authenticated())
                                .sessionManagement(sess -> sess.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                                .authenticationProvider(authenticationProvider)
                                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                                .oauth2Login(oauth2 -> oauth2
                                                .authorizationEndpoint(authorization -> authorization
                                                                .baseUri("/oauth2/authorize"))
                                                .redirectionEndpoint(redirection -> redirection
                                                                .baseUri("/oauth2/callback/*"))
                                                .userInfoEndpoint(userInfo -> userInfo
                                                                .userService(oauth2UserService()))
                                                .successHandler(oAuth2AuthenticationSuccessHandler())
                                                .failureHandler(oAuth2AuthenticationFailureHandler()));

                return http.build();
        }

        @Bean
        public OAuth2UserService<OAuth2UserRequest, OAuth2User> oauth2UserService() {
                DefaultOAuth2UserService delegate = new DefaultOAuth2UserService();
                return (userRequest) -> {
                        OAuth2User oauth2User = delegate.loadUser(userRequest);
                        // TODO: Process the OAuth2User, create or update user in your system
                        return oauth2User;
                };
        }

        @Bean
        public AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler() {
                return (request, response, authentication) -> {
                        // TODO: Generate JWT token and redirect to frontend with token
                        response.sendRedirect("/");
                };
        }

        @Bean
        public AuthenticationFailureHandler oAuth2AuthenticationFailureHandler() {
                return (request, response, exception) -> {
                        // TODO: Handle authentication failure
                        response.sendRedirect("/login?error=oauth2_error");
                };
        }
}