package com.gopang.client.controller;

import com.gopang.client.entity.User;
import com.gopang.client.entity.VerificationToken;
import com.gopang.client.event.RegisterationCompleteEvent;
import com.gopang.client.model.PasswordModel;
import com.gopang.client.model.UserModel;
import com.gopang.client.service.UserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.Optional;
import java.util.UUID;

@RestController
@Slf4j
public class RegistrationController {

    @Autowired
    private UserService userService;

    @Autowired
    private ApplicationEventPublisher publisher;

    //회원가입 api
    @PostMapping("/register")
    public String registerUser(@RequestBody UserModel userModel, final HttpServletRequest request){
        User user = userService.registerUser(userModel);
        publisher.publishEvent(new RegisterationCompleteEvent(
                user,applicationUrl(request)
        ));
        return "회원 가입 성공입니닷!>.< ㅊㅋㅊㅋ";


    }

    // 토큰을 검증
    @GetMapping("/verifyRegistration")
    public String verifyRegistration(@RequestParam("token") String token){
        String result = userService.validateVerificationToken(token);
        if(result.equalsIgnoreCase("valid")){
            return "유저 증명 오케이!";
        }
        return "유저 증명 잘못됨!";
    }

    //새로운 토큰을 가져오는 엔드포인트
    @GetMapping("/resendVerifyToken")
    public String resendVerificationToken(@RequestParam("token") String oldToken,
                                          HttpServletRequest request){
        VerificationToken verificationToken
                = userService.generateNewVerificationToken(oldToken);
        User user = verificationToken.getUser();
        resendVerificationTOkenMail(user,applicationUrl(request),verificationToken);
        return "새로운 자격증명(토큰)을 보내드렸어요!";

    }


    // 비번 변경을 위한 리셋 토큰 생성
    @PostMapping("/resetPassword")
    public String resetPassword(@RequestBody PasswordModel passwordModel,HttpServletRequest request) {
        User user = userService.findUserByEmail(passwordModel.getEmail());
        String url = "";
        if(user != null){
            String token = UUID.randomUUID().toString();
            userService.createPasswordResetTokenForUser(user,token);
            url = passwordResetTokenMail(user,applicationUrl(request),token);

        }
        return url;

    }

    // 비번 변경을 위한 리셋 토큰을 저장하고 비변 변경을 했지만 저장이 안된,
    @PostMapping("/savePassword")
    public String savePassword(@RequestParam("token") String token,
                               @RequestBody PasswordModel passwordModel) {
        String result = userService.validatePasswordResetToken(token);
        if(!result.equalsIgnoreCase("valid")){
            return "Invalid Tok908989en";
        }
        Optional<User> user = userService.getUserByPasswordResetToken(token);
        if(user.isPresent()){
            userService.changePassword(user.get(),passwordModel.getNewPassword());
            return "비번 변경 성공!";
        } else {
            return "비번 변경 실패!";
        }

    }

    // 비밀번호 변경을 완료하는 api
    @PostMapping("/changePassword")
    public String changePassword(@RequestBody PasswordModel passwordModel){
        User user = userService.findUserByEmail(passwordModel.getEmail());
        if(userService.checkIfValidOldPass(user,passwordModel.getOldPassword())){
            return "유효하지 않습니다.";
        }

        // 새로운 비번 저장
        userService.changePassword(user,passwordModel.getNewPassword());
        return "비번 변경이 완료 됐습니다.";

    }



    private String passwordResetTokenMail(User user, String applicationUrl,String token) {
        String url = applicationUrl
                + "/savePassword?token="
                + token;
        //이메일로 인증 발송!
        log.info("Click the link to Reset your Password: {}",
                url);
        return url;
    }

    private void resendVerificationTOkenMail(User user, String applicationUrl, VerificationToken verificationToken) {
        String url = applicationUrl
                + "/verifyRegistration?token="
                + verificationToken.getToken();
        //이메일로 인증 발송!
        log.info("Click the link to verify your account: {}",
                url);
    }

    private String applicationUrl(HttpServletRequest request) {
        return "http://" +
                request.getServerName()+
                ":"+
                request.getServerPort()+
                request.getContextPath();
    }
}
