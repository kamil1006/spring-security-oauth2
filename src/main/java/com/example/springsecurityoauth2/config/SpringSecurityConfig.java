package com.example.springsecurityoauth2.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.WebSecurityConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Collection;
import java.util.Collections;

@Configuration
public class SpringSecurityConfig /*
        extends WebSecurityConfigurerAdapter {

    @Bean
   public PasswordEncoder getBCryptPasswordEncoder(){
       return new BCryptPasswordEncoder();
   }


    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //super.configure(auth);
        User user = new User("jan",
                getBCryptPasswordEncoder().encode("jan"),
                Collections.singleton(new SimpleGrantedAuthority("ROLE_USER")));
        User admin = new User("naj",
                getBCryptPasswordEncoder().encode("naj"),
                Collections.singleton(new SimpleGrantedAuthority("ROLE_ADMIN")));

auth.inMemoryAuthentication().withUser(user).withUser(admin);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
       // super.configure(http);
        http.authorizeRequests()
                .antMatchers("/for-user").hasAnyRole("USER", "ADMIN")
                .antMatchers("/for-admin").hasAnyRole("ADMIN")
               // .antMatchers("/for-admin").hasAuthority("ROLE_ADMIN")
                .and()
                .formLogin().permitAll()
                .and()
                .logout().logoutUrl("/bye");




    }
}
*/
{




}