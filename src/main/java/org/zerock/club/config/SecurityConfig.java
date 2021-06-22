package org.zerock.club.config;

import lombok.extern.log4j.Log4j2;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@Log4j2
public class SecurityConfig extends WebSecurityConfigurerAdapter {


    @Bean
    PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();

    }


    @Override
    protected void configure(HttpSecurity http) throws Exception{


        http.authorizeRequests()
                .antMatchers("/sample/all").permitAll();

    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception{

        //사용자 계정 user1
        auth.inMemoryAuthentication().withUser("user1")

                //패스워드 1111 인코딩 결과
                .password("$2a$10$0m61yldh6nDaEayHoq5GueKkQnCMnerJ2QkpMmPxPVGMPBA8ES1.a")
                .roles("USER");

    }

}
