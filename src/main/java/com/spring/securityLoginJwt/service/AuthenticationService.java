package com.spring.securityLoginJwt.service;

import com.spring.securityLoginJwt.model.AuthenticationResponse;
import com.spring.securityLoginJwt.model.User;
import com.spring.securityLoginJwt.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthenticationService {
    @Autowired
    private UserRepository userRepository;

    @Autowired
    private JwtService jwtService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    private final AuthenticationManager authenticationManager;

    public AuthenticationService(UserRepository userRepository,
                                 JwtService jwtService,
                                 PasswordEncoder passwordEncoder,
                                 AuthenticationManager authenticationManager) {
        this.userRepository = userRepository;
        this.jwtService = jwtService;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
    }

    public AuthenticationResponse register(User request) {

        // check if user already exist. if exist than authenticate the user
        if(userRepository.findByUsername(request.getUsername()).isPresent()) {
            return new AuthenticationResponse(null, "User already exist");
        }

        User user = new User();
        user.setFirstName(request.getFirstName());
        user.setLastName(request.getLastName());
        user.setUsername(request.getUsername());
        user.setPassword(passwordEncoder.encode(request.getPassword()));


        user.setRole(request.getRole());

        user = userRepository.save(user);

        String jwt = jwtService.generateToken(user);

       // saveUserToken(jwt, user);

        return new AuthenticationResponse(jwt, "User registration was successful");

    }
    public AuthenticationResponse authenticate(User request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getUsername(),
                        request.getPassword()
                )
        );

        User user = userRepository.findByUsername(request.getUsername()).orElseThrow();
        String jwt = jwtService.generateToken(user);

       // revokeAllTokenByUser(user);
       // saveUserToken(jwt, user);

        return new AuthenticationResponse(jwt, "User login was successful");

    }






}
