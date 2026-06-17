package com.backend.devsecopsplatform_backend.util;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;

import java.util.LinkedHashMap;
import java.util.Map;

public final class SecurityAlertDetailsBuilder {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private SecurityAlertDetailsBuilder() {}

    public static String fromRequest(
            HttpServletRequest request,
            String path,
            String query,
            String userAgent,
            String threatCategory,
            String threatDetail) {
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("method", request.getMethod());
        details.put("path", path);
        details.put("query", query);
        details.put("fullUrl", buildFullUrl(path, query));
        details.put("ip", request.getRemoteAddr());
        details.put("userAgent", userAgent);
        details.put("threatCategory", threatCategory);
        details.put("threatDetail", threatDetail);
        Map<String, String> headers = new LinkedHashMap<>();
        addHeader(headers, request, "X-Forwarded-For");
        addHeader(headers, request, "X-Real-IP");
        addHeader(headers, request, "Referer");
        addHeader(headers, request, "Accept");
        addHeader(headers, request, "Accept-Language");
        details.put("headers", headers);
        return toJson(details);
    }

    public static String simple(Map<String, Object> fields) {
        return toJson(fields);
    }

    private static void addHeader(Map<String, String> headers, HttpServletRequest request, String name) {
        String value = request.getHeader(name);
        if (value != null && !value.isBlank()) {
            headers.put(name, value);
        }
    }

    private static String buildFullUrl(String path, String query) {
        if (query == null || query.isBlank()) {
            return path;
        }
        return path + "?" + query;
    }

    private static String toJson(Map<String, Object> details) {
        try {
            return MAPPER.writeValueAsString(details);
        } catch (JsonProcessingException e) {
            return "{}";
        }
    }
}
