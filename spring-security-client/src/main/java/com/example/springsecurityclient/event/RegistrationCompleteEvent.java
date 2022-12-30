package com.example.springsecurityclient.event;

import com.example.springsecurityclient.entity.User;
import lombok.Getter;
import org.springframework.context.ApplicationEvent;

@Getter
public class RegistrationCompleteEvent extends ApplicationEvent {

    private final User user;
    private final String applicationUrl;

    public RegistrationCompleteEvent(User user, String applicationUrl) {
        super(user);

        this.user = user;
        this.applicationUrl = applicationUrl;
    }
}
