package com.mjamsek.auth.keycloak.models;

import javax.ws.rs.core.MultivaluedMap;
import java.util.List;

public class AuthContext {
    
    private String id;
    
    private String username;
    
    private String email;
    
    private List<String> realmRoles;
    
    private MultivaluedMap<String, String> clientRoles;
    
    private List<String> scopes;
    
    private boolean authenticated;
    
    public static AuthContext empty() {
        AuthContext context = new AuthContext();
        context.authenticated = false;
        return context;
    }
    
    public boolean hasRealmRole(String role) {
        return realmRoles.contains(role);
    }
    
    public boolean hasClientRole(String clientId, String role) {
        if (clientRoles.containsKey(clientId)) {
            return clientRoles.get(clientId).contains(role);
        }
        return false;
    }
    
    public boolean hasScope(String scope) {
        return scopes.contains(scope);
    }
    
    public boolean hasRole(String role) {
        if (hasRealmRole(role)) {
            return true;
        }
        for (String clientId : clientRoles.keySet()) {
            if (hasClientRole(clientId, role)) {
                return true;
            }
        }
        return false;
    }
    
    public List<String> getClientRoles(String clientId) {
        if (clientRoles.containsKey(clientId)) {
            return clientRoles.get(clientId);
        }
        return null;
    }
    
    public String getId() {
        return id;
    }
    
    public void setId(String id) {
        this.id = id;
    }
    
    public String getUsername() {
        return username;
    }
    
    public void setUsername(String username) {
        this.username = username;
    }
    
    public String getEmail() {
        return email;
    }
    
    public void setEmail(String email) {
        this.email = email;
    }
    
    public List<String> getRealmRoles() {
        return realmRoles;
    }
    
    public void setRealmRoles(List<String> realmRoles) {
        this.realmRoles = realmRoles;
    }
    
    public MultivaluedMap<String, String> getClientRoles() {
        return clientRoles;
    }
    
    public void setClientRoles(MultivaluedMap<String, String> clientRoles) {
        this.clientRoles = clientRoles;
    }
    
    public List<String> getScopes() {
        return scopes;
    }
    
    public void setScopes(List<String> scopes) {
        this.scopes = scopes;
    }
    
    public boolean isAuthenticated() {
        return authenticated;
    }
    
    public void setAuthenticated(boolean authenticated) {
        this.authenticated = authenticated;
    }
}
