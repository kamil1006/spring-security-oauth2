package com.example.springsecurityoauth2.controler;


import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
public class TestController {

@GetMapping("/for-all")
    public String getForAll(){

    return "hello you!";
}

    @GetMapping("/for-user")
    public String getForUser(){

        return "helol juser!";
    }


    @GetMapping("/for-admin")
    public String getForAdmin(){

        return "helol admin!";
    }

    @GetMapping("/bye")
    public String getBye(){

        return "pa a bye";
    }


    @GetMapping("/for-all-face")
    public String getForAllFacebook(Principal principal){

        Object[] objects = ((OAuth2AuthenticationToken) principal).getAuthorities().stream().toArray();
        Object name = ((OAuth2UserAuthority) objects[0]).getAttributes().get("name");

        return "hello you "+principal.getName()+" inaczej "+name+" !";
    }



}
