package com.example.bola_security.config;

import com.example.bola_security.filter.BolaSecurityFilter;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class FilterConfig {

    @Bean
    public FilterRegistrationBean<BolaSecurityFilter> bolaFilter(BolaSecurityFilter filter) {
        FilterRegistrationBean<BolaSecurityFilter> registration = new FilterRegistrationBean<>();

        registration.setFilter(filter);
        registration.addUrlPatterns("/api/*");
        registration.setOrder(1);

        return registration;
    }
}