package com.github.axfyz.sanidy.config;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;
import lombok.Data;

@Data
@ConfigurationProperties("sanidy")
public class SanidyProperties {
    private List<String> blockedHosts = new ArrayList<>(Arrays.asList());

    private List<String> sqlKeywords = new ArrayList<>(Arrays.asList(
            "SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "UNION",
            "ALTER", "CREATE", "EXEC", "TRUNCATE", "--", "/*", "*/", "0x"));

    private List<String> urlSchemes = new ArrayList<>(Arrays.asList(
            "http://", "https://", "ftp://", "file://",
            "dict://", "gopher://", "ldap://", "://"));

    private List<String> xssPatterns = new ArrayList<>(Arrays.asList(
            "<script", "javascript:", "onerror=", "onload=",
            "onclick=", "<iframe", "<svg", "alert(", "eval("));
}
