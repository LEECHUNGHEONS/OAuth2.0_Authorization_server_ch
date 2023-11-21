package com.gopang.client.event.listener;

import com.gopang.client.entity.User;
import com.gopang.client.event.RegisterationCompleteEvent;

import com.gopang.client.service.UserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationListener;
import org.springframework.stereotype.Component;

import java.util.UUID;

@Slf4j
@Component
public class RegistrationCompleteEventListener implements
        ApplicationListener<RegisterationCompleteEvent> {

    @Autowired
    private UserService userService;
    @Override
    public void onApplicationEvent(RegisterationCompleteEvent event) {
        //링크를 누른 사용자에게 권한토큰을 생성
        User user = event.getUser();
        String token = UUID.randomUUID().toString();
        userService.saveVerificationTokenForUser(token,user);
        //유저(사용자)에게 메일 보냄
        String url = event.getApplicationUrl()
                + "/verifyRegistration?token="
                + token;
        //이메일로 인증 발송!
        log.info("Click the link to verify your account: {}",
                url);
    }
}
