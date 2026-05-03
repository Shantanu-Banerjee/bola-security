package com.example.bola_security;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.cache.annotation.EnableCaching;

@SpringBootApplication
@ConfigurationPropertiesScan
@EnableCaching
public class BolaSecurityApplication {

	public static void main(String[] args) {
		SpringApplication.run(BolaSecurityApplication.class, args);
	}

}
