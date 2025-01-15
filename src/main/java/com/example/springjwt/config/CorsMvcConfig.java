package com.example.springjwt.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class CorsMvcConfig implements WebMvcConfigurer {

    @Override
    public void addCorsMappings(CorsRegistry corsRegistry) {

        //모든 url경로에 아래의 origin 허용
        corsRegistry.addMapping("/**")
                .allowedOrigins("http://localhost:3000");
    }
}