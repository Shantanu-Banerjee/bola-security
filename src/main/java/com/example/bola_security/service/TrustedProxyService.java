package com.example.bola_security.service;

import com.example.bola_security.config.BolaSecurityProperties;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Service;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Locale;

@Service
public class TrustedProxyService {

    private final BolaSecurityProperties properties;

    public TrustedProxyService(BolaSecurityProperties properties) {
        this.properties = properties;
    }

    public String resolveClientIp(HttpServletRequest request) {
        String remoteAddress = request.getRemoteAddr();
        if (!isTrustedProxy(remoteAddress)) {
            return remoteAddress;
        }

        String forwardedFor = request.getHeader("X-Forwarded-For");
        if (forwardedFor != null && !forwardedFor.isBlank()) {
            String clientIp = forwardedFor.split(",")[0].trim();
            if (isValidIp(clientIp)) {
                return clientIp;
            }
        }

        String realIp = request.getHeader("X-Real-IP");
        if (realIp != null && !realIp.isBlank() && isValidIp(realIp.trim())) {
            return realIp.trim();
        }

        return remoteAddress;
    }

    private boolean isTrustedProxy(String remoteAddress) {
        if (remoteAddress == null || remoteAddress.isBlank()) {
            return false;
        }
        return properties.trustedProxies().stream()
                .map(String::trim)
                .filter(value -> !value.isBlank())
                .anyMatch(value -> matches(remoteAddress, value));
    }

    private boolean matches(String remoteAddress, String trustedProxy) {
        if (trustedProxy.contains("/")) {
            return cidrMatches(remoteAddress, trustedProxy);
        }
        return remoteAddress.equalsIgnoreCase(trustedProxy);
    }

    private boolean cidrMatches(String remoteAddress, String cidr) {
        String[] parts = cidr.split("/", 2);
        if (parts.length != 2 || remoteAddress.contains(":") || parts[0].contains(":")) {
            return false;
        }
        try {
            int prefixLength = Integer.parseInt(parts[1]);
            if (prefixLength < 0 || prefixLength > 32) {
                return false;
            }
            int remote = ipv4ToInt(remoteAddress);
            int network = ipv4ToInt(parts[0]);
            int mask = prefixLength == 0 ? 0 : -1 << (32 - prefixLength);
            return (remote & mask) == (network & mask);
        } catch (IllegalArgumentException exception) {
            return false;
        }
    }

    private int ipv4ToInt(String ip) {
        String[] octets = ip.split("\\.");
        if (octets.length != 4) {
            throw new IllegalArgumentException("Invalid IPv4 address");
        }
        int value = 0;
        for (String octet : octets) {
            int parsed = Integer.parseInt(octet);
            if (parsed < 0 || parsed > 255) {
                throw new IllegalArgumentException("Invalid IPv4 octet");
            }
            value = (value << 8) | parsed;
        }
        return value;
    }

    private boolean isValidIp(String value) {
        String trimmed = value.toLowerCase(Locale.ROOT);
        if (trimmed.contains("\r") || trimmed.contains("\n")) {
            return false;
        }
        boolean looksLikeIpLiteral = trimmed.matches("[0-9.]+") || trimmed.matches("[0-9a-f:.%]+");
        if (!looksLikeIpLiteral) {
            return false;
        }
        try {
            InetAddress.getByName(trimmed);
            return true;
        } catch (UnknownHostException exception) {
            return false;
        }
    }
}
