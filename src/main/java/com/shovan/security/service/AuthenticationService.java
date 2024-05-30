package com.shovan.security.service;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.shovan.security.dto.AuthenticationRequest;
import com.shovan.security.dto.AuthenticationResponse;
import com.shovan.security.dto.EnableDisableRequest;
import com.shovan.security.dto.PasswordResetRequest;
import com.shovan.security.dto.RegisterRequest;
import com.shovan.security.entity.Role;
import com.shovan.security.entity.User;
import com.shovan.security.repository.UserRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

        private final UserRepository userRepository;

        private final PasswordEncoder passwordEncoder;

        private final JwtService jwtService;

        private final AuthenticationManager authenticationManager;

        public AuthenticationResponse register(RegisterRequest request) {

                var user = User.builder()
                                .firstName(request.getFirstname())
                                .lastName(request.getLastname())
                                .email(request.getEmail())
                                .password(passwordEncoder.encode(request.getPassword()))
                                .role(Role.USER)
                                .build();

                userRepository.save(user);

                var jwtToken = jwtService.generateToken(user);

                return AuthenticationResponse.builder()
                                .token(jwtToken)
                                .build();
        }

        public AuthenticationResponse authenticate(AuthenticationRequest request) {

                authenticationManager.authenticate(
                                new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword()));

                User user = userRepository.findByEmail(request.getEmail())
                                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
                if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
                        throw new BadCredentialsException("Invalid credentials");
                }

                var jwtToken = jwtService.generateToken(user);

                return AuthenticationResponse.builder()
                                .token(jwtToken)
                                .build();
        }

        public void resetPassword(PasswordResetRequest request) {
                User user = userRepository.findByEmail(request.getEmail())
                                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
                user.setPassword(passwordEncoder.encode(request.getNewPassword()));
                userRepository.save(user);
        }

        public void enableDisableAccount(EnableDisableRequest request) {
                User user = userRepository.findByEmail(request.getEmail())
                                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
                user.setEnabled(request.isEnabled());
                userRepository.save(user);
        }

}
