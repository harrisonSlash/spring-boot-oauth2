package com.example.oauth2.poc.infrastructure.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class AppController {

    private static final Logger log = LoggerFactory.getLogger(AppController.class);

    @Secured("ROLE_ADMIN")
    @GetMapping("/restricted")
    public String loadRestrictedPage(@AuthenticationPrincipal OAuth2User principal) {
        return "html/restricted";
    }

    @GetMapping("/home")
    public String loadHomePage() {
        return "html/home";
    }

    @GetMapping("/loginSuccess")
    public String loadLoginSuccessPage(@AuthenticationPrincipal OAuth2User principal) {
        log.info( "principal: {} ", principal);
        return "html/login-success";
    }

    @GetMapping("/loginFailure")
    public String loadLoginFailurePage() {
        return "html/login-failure";
    }
}
