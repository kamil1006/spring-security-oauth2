package com.example.springsecurityoauth2.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import java.util.Arrays;

@Configuration
@EnableWebSecurity

public class SpringSecurityConfigNew {
    @Bean
    public PasswordEncoder getBCryptPasswordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public InMemoryUserDetailsManager get(){
        UserDetails user = User.withUsername("jan")
                .password(getBCryptPasswordEncoder().encode("jan"))
                .roles("USER")
                .build();

        UserDetails admin = User.withUsername("naj")
                .password(getBCryptPasswordEncoder().encode("naj"))
                .roles("ADMIN")
                .build();

        return new InMemoryUserDetailsManager(Arrays.asList(user,admin));
    }







    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

//          http.authorizeRequests()
//                .antMatchers("/for-user").hasAnyRole("USER", "ADMIN")
//                .antMatchers("/for-admin").hasAnyRole("ADMIN")
//                // .antMatchers("/for-admin").hasAuthority("ROLE_ADMIN")
//                .and()
//                .formLogin().permitAll()
//                .and()
//                .logout().logoutUrl("/bye");


//        http
//                .authorizeRequests((autz) -> autz
//
//                .antMatchers("/for-user").hasAnyRole("USER", "ADMIN")
//                .antMatchers("/for-admin").hasAnyRole("ADMIN")
//
//        )
//                .formLogin((formLogin)->formLogin.permitAll())
//                .logout()
//                // .deleteCookies("Cookies")
//                .logoutSuccessUrl("/bye").permitAll() ;


//  ostatnie sprawdzone
//
//        http.authorizeRequests((requests) -> requests
//                .requestMatchers("/for-user").hasAnyRole("USER", "ADMIN")
//                .requestMatchers("/for-admin").hasAnyRole("ADMIN")
//               //                 .requestMatchers("/logout").permitAll()
//                )
//                .formLogin((formLogin) -> formLogin.permitAll())
//                .logout()
//                // .deleteCookies("Cookies")
//                .logoutSuccessUrl("/bye").permitAll() ;


        // do logowania przy pomocy facebooka

        http.authorizeRequests((requests) -> requests
                                .anyRequest().authenticated()
                        //                 .requestMatchers("/logout").permitAll()
                )
                .oauth2Login()
                .and()
                .formLogin((formLogin) -> formLogin.permitAll())
                .logout((logout) -> logout.logoutSuccessUrl("/bye").permitAll())

                ;

        return http.build();
    }

}
