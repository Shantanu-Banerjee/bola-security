package com.example.bola_security.config;

import com.example.bola_security.filter.BolaSecurityFilter;
import jakarta.servlet.Filter;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class FilterConfig {

    private final BolaSecurityFilter bolaSecurityFilter;

    public FilterConfig(BolaSecurityFilter bolaSecurityFilter) {
        this.bolaSecurityFilter = bolaSecurityFilter;
    }

    @Bean
    public FilterRegistrationBean<Filter> bolaFilter() {
        FilterRegistrationBean<Filter> registration = new FilterRegistrationBean<>();
        registration.setFilter(bolaSecurityFilter);
        registration.addUrlPatterns("/*");
        registration.setOrder(3); // After Spring Security oauth2ResourceServer (order 2)
        return registration;
    }
}