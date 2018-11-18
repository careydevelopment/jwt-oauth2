package com.careydevelopment.oauth2.resource.config;

import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
@EnableWebMvc
@ComponentScan({ "com.careydevelopment.oauth2.resource.controller" })
public class ResourceServerWebConfig implements WebMvcConfigurer {
    //
}
