package com.gopang.authorizationserver.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

/*
   사용자 인증을 커스텀해서 처리
 */
@Service
public class CustomAuthenticationProvider implements AuthenticationProvider {

    @Autowired // 커스텀 된 사용자 정보를 가져옴
    private CustomUserDetailService customUserDetailService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    /*
      사용자 인증정보를 기반으로 인증을 수행 loadUserByUsername으로 사용자 정보를 찾아옴
      checkPassword 를 호출하여 제공된 비밀번호가 올바른지 확인.
     */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String password = authentication.getCredentials().toString();
        UserDetails user = customUserDetailService.loadUserByUsername(username);
        return checkPassword(user,password);
    }

    // passwordEncoder.matches를 사용하여 제공된 비번이 실제 비번과 일치하는지 확인
    private Authentication checkPassword(UserDetails user, String rawPassword) {
        if(passwordEncoder.matches(rawPassword, user.getPassword())){
            return new UsernamePasswordAuthenticationToken(user.getUsername(),
                    user.getPassword(), user.getAuthorities());
        }
        else {
            throw  new BadCredentialsException("잘못된 암호입니다.");
        }
    }

    // UsernamePasswordAuthenticationToken을 지원하는지 여부 확인 및 처리할수 있는지 확인
    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
