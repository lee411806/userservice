package com.example.springjwt.config;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

//sercurity를 위한 configuration
@Configuration
@EnableWebSecurity
/*이 애너테이션이 없으면 Spring Boot의 기본 보안 설정이 적용됨.
이 애너테이션이 있으면, 정의된 보안 설정 클래스(SecurityConfig)를 기반으로 동작.*/
public class SecurityConfig {


    // 비밀번호 단방향으로 암호화(복호화 안됨), 서버가 암호화 시켜서 저장해 놓는다.
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {

        return new BCryptPasswordEncoder();
    }



    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        //csrf disabled
        // csrf에 대한 공격을 방버하지 않아도 됨(jwt)

        http.csrf((auth) -> auth.disable());

        //Form 로그인 방식 disable
        http
                .formLogin((auth) -> auth.disable());

        //http basic 인증 방식 disable
        //basic인증이 header에 아이디 비밀번호보내는건데 이게 보안에 취약해서 허용하지 않는것임
        http
                .httpBasic((auth) -> auth.disable());

        //경로별 인가 작업
        // 모든 사용자가 접근가능 api, ADMIN사용자만 접근가능한 api설정
        http
                .authorizeHttpRequests((auth) -> auth
                        .requestMatchers("/login", "/", "/join").permitAll()
                        .requestMatchers("/admin").hasRole("ADMIN")
                        .anyRequest().authenticated());

        //세션 설정
        http
                .sessionManagement((session) -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        return http.build();
    }
}
