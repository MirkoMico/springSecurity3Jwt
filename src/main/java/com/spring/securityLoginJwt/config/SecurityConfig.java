package com.spring.securityLoginJwt.config;

import com.spring.securityLoginJwt.filter.JwtAuthenticationFilter;
import com.spring.securityLoginJwt.service.UserDetailsServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    //@Autowired
    private final UserDetailsServiceImpl userDetailsServiceImpl;
   // @Autowired
    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    @Autowired
    private CustomLogoutHandler logoutHandler;

    public SecurityConfig(UserDetailsServiceImpl userDetailsServiceImpl, JwtAuthenticationFilter jwtAuthenticationFilter) {
        this.userDetailsServiceImpl = userDetailsServiceImpl;
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
    }


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
       return http
                .csrf(AbstractHttpConfigurer ::disable)
               .authorizeHttpRequests(
                   req-> req.requestMatchers("/login/**", "/register/**")
                       .permitAll()
                       .requestMatchers("/admin_only/**").hasAuthority("ADMIN")//le chiamate che possono fare solo gli admin
                       .anyRequest()
                       .authenticated()
               ).userDetailsService(userDetailsServiceImpl)
               .sessionManagement(session->session
                       .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
               .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
               .logout(l->l
                       .logoutUrl("/logout")
                       .addLogoutHandler(logoutHandler)
                       .logoutSuccessHandler((request, response, authentication) -> SecurityContextHolder.clearContext()
                       ))
               .build();

    }
    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder() ;
    }
    @Bean
    public AuthenticationManager authenticationManager (AuthenticationConfiguration configuration)throws Exception{
        return configuration.getAuthenticationManager();
    }
}
