package com.mjamsek.auth.keycloak.models;

import javax.ws.rs.HeaderParam;
import javax.ws.rs.PathParam;

public class ServiceCallBeanParam {
    
    @PathParam("realm")
    private String realm;
    
    @HeaderParam("Authorization")
    private String authorizationHeader;
    
    public String getRealm() {
        return realm;
    }
    
    public void setRealm(String realm) {
        this.realm = realm;
    }
    
    public String getAuthorizationHeader() {
        return authorizationHeader;
    }
    
    public void setAuthorizationHeader(String authorizationHeader) {
        this.authorizationHeader = authorizationHeader;
    }
}
