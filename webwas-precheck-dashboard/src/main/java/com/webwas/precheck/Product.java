package com.webwas.precheck;

import java.util.Locale;

/**
 * 점검 대상 제품. 리포트 첫 줄(머리글)과 파일명 접두어로 구분.
 *  - Apache httpd  : apache_precheck.sh  → apache_precheck_<호스트>_<시각>.txt
 *  - WildFly       : wildfly_precheck.sh → wildfly_precheck_<호스트>_<시각>.txt
 *  - Apache Tomcat : tomcat_precheck.sh  → tomcat_precheck_<호스트>_<시각>.txt
 *  - Nginx         : nginx_precheck.sh   → nginx_precheck_<호스트>_<시각>.txt
 * 순서가 점검 스크립트 SHA-256 계산 순서(에이전트 ALL_PRODUCTS)와 같아야 함.
 */
public enum Product {
    APACHE("apache", "Apache", "apache_precheck.sh", "Apache 패치 전 보안 사전 점검"),
    WILDFLY("wildfly", "WildFly", "wildfly_precheck.sh", "WildFly 패치 전 보안 사전 점검"),
    TOMCAT("tomcat", "Tomcat", "tomcat_precheck.sh", "Tomcat 패치 전 보안 사전 점검"),
    NGINX("nginx", "Nginx", "nginx_precheck.sh", "Nginx 패치 전 보안 사전 점검");

    public final String id;
    public final String label;
    public final String script;
    public final String headerMark;

    Product(String id, String label, String script, String headerMark) {
        this.id = id;
        this.label = label;
        this.script = script;
        this.headerMark = headerMark;
    }

    /** 지원 브랜치마다 최신 버전을 따로 두는 제품 (Tomcat 11.0/10.1/9.0, Nginx mainline/stable). 목록에 없는 브랜치 = 지원 종료 */
    public boolean branched() {
        return this == TOMCAT || this == NGINX;
    }

    /** CVE 를 "버전 + 필요 모듈(기능) 조건"으로 판정하고 패키지 changelog 로 백포트를 추정하는 제품 (Apache, Nginx) */
    public boolean moduleStyle() {
        return this == APACHE || this == NGINX;
    }

    /** 조건 칸 이름: Apache "필요 모듈", Nginx "필요 기능" */
    public String conditionLabel() {
        return this == NGINX ? "필요 기능" : "필요 모듈";
    }

    /** 리포트 파일명 접두어 (예: "tomcat_precheck_") */
    public String reportPrefix() {
        return id + "_precheck_";
    }

    public static Product byId(String id) {
        if (id == null) return null;
        String s = id.trim().toLowerCase(Locale.ROOT);
        for (Product p : values()) {
            if (p.id.equals(s)) return p;
        }
        return null;
    }

    /** 리포트 본문 첫 줄의 머리글로 판별. 모르면 null */
    public static Product fromText(String text) {
        if (text == null) return null;
        int nl = text.indexOf('\n');
        String first = nl < 0 ? text : text.substring(0, nl);
        for (Product p : values()) {
            if (first.contains(p.headerMark)) return p;
        }
        return null;
    }

    /** 파일명(agent-xxx__ 접두어 포함 가능)으로 판별. 모르면 null */
    public static Product fromFileName(String name) {
        if (name == null) return null;
        String n = name.contains("__") ? name.substring(name.indexOf("__") + 2) : name;
        for (Product p : values()) {
            if (n.startsWith(p.reportPrefix())) return p;
        }
        return null;
    }
}
