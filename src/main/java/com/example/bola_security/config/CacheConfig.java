package com.example.bola_security.config;

import org.springframework.boot.autoconfigure.cache.RedisCacheManagerBuilderCustomizer;
import org.springframework.boot.autoconfigure.cache.CacheManagerCustomizer;
import org.springframework.cache.concurrent.ConcurrentMapCacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.cache.RedisCacheConfiguration;

import java.time.Duration;

@Configuration
public class CacheConfig {

    @Bean
    public RedisCacheManagerBuilderCustomizer redisCacheManagerBuilderCustomizer() {
        return builder -> builder
                .withCacheConfiguration("userAccounts", cacheConfiguration(Duration.ofMinutes(15)))
                .withCacheConfiguration("accessPolicyDecisions", cacheConfiguration(Duration.ofMinutes(5)));
    }

    @Bean
    public CacheManagerCustomizer<ConcurrentMapCacheManager> concurrentMapCacheManagerCustomizer() {
        return cacheManager -> cacheManager.setCacheNames(java.util.List.of("userAccounts", "accessPolicyDecisions"));
    }

    private RedisCacheConfiguration cacheConfiguration(Duration ttl) {
        return RedisCacheConfiguration.defaultCacheConfig().entryTtl(ttl);
    }
}
