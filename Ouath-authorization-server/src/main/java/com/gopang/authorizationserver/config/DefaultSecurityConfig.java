package com.gopang.authorizationserver.config;

import com.gopang.authorizationserver.service.CustomAuthenticationProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
public class DefaultSecurityConfig {

    @Autowired
    private CustomAuthenticationProvider customAuthenticationProvider;

    // http 보안을 구성 , httpSecurity를 사용하여 http 요청에 대한 인가 규칙을 설정
    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
            throws Exception {
        http.authorizeHttpRequests(authorizeHttpRequests ->
                            authorizeHttpRequests.anyRequest().authenticated()
                ) //  모든요청에 인증 요구
                .formLogin(Customizer.withDefaults());

        return http.build();
    }

    /*
       이 메서드는 AuthenticationManagerBuilder를 이용하여 커스텀한 인증 프로바이더를 바인더 하는 역활
     */
    @Autowired
    public void bindAuthenticationProvider(AuthenticationManagerBuilder authenticationManagerBuilder){
        authenticationManagerBuilder
                .authenticationProvider(customAuthenticationProvider);
    }

}
