package com.ankit.authserver.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;


@EnableWebSecurity
@Configuration
public class DefaultSecurityConfig {
	
	@Bean
	UserDetailsService users() {
	    UserDetails user = User.withDefaultPasswordEncoder()
	      .username("admin")
	      .password("password")
	      .build();
	    return new InMemoryUserDetailsManager(user);
	}
	
	@Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorizeRequests ->
          authorizeRequests.anyRequest().authenticated()
        )
          .formLogin(withDefaults());
        return http.build();
    }

}
