package com.gopang.client.event;

import com.gopang.client.entity.User;
import com.gopang.client.service.UserService;
import lombok.Getter;
import lombok.Setter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEvent;
import org.springframework.stereotype.Component;

@Setter
@Getter
public class RegisterationCompleteEvent extends ApplicationEvent {

    private User user;

    private String applicationUrl;
    public RegisterationCompleteEvent(User user,String applicationUrl) {
        super(user);
        this.user = user;
        this.applicationUrl = applicationUrl;
    }
}
