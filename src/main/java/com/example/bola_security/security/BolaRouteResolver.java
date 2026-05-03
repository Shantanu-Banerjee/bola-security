package com.example.bola_security.security;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Component;

import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Component
public class BolaRouteResolver {

    private static final Pattern RESOURCE_DETAIL_ROUTE = Pattern.compile("^/api/v1/resources/(?<id>\\d+)$");

    public Optional<BolaRouteMatch> resolve(HttpServletRequest request) {
        Matcher matcher = RESOURCE_DETAIL_ROUTE.matcher(request.getRequestURI());
        if (!matcher.matches()) {
            return Optional.empty();
        }
        return Optional.of(new BolaRouteMatch(Long.parseLong(matcher.group("id"))));
    }
}
