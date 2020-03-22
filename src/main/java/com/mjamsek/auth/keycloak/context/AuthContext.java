package com.mjamsek.auth.keycloak.context;

import javax.ws.rs.core.MultivaluedMap;
import java.util.List;
import java.util.Map;

public class AuthContext {
    
    /**
     * User id, retrieved from JWT subject
     */
    String id;
    
    /**
     * Username, retrieved from JWT. By default field <tt>preferred_username</tt> is used,
     * but it can be changed in configuration using key <tt>kc.claims.username</tt>
     */
    String username;
    
    /**
     * User email, retrieved from JWT. By default field <tt>email</tt> is used,
     * but it can be changed in configuration using key <tt>kc.claims.email</tt>
     */
    String email;
    
    /**
     * User realm roles
     */
    List<String> realmRoles;
    
    /**
     * User client roles
     */
    MultivaluedMap<String, String> clientRoles;
    
    /**
     * User scopes
     */
    List<String> scopes;
    
    /**
     * Is true, when auth context is constructed
     */
    boolean authenticated;
    
    /**
     * Map of all other claims
     */
    Map<String, Object> claims;
    
    /**
     * Raw JWT token
     */
    String rawToken;
    
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
    
    public boolean hasClaim(String claim) {
        return claims.containsKey(claim);
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
    
    public String getUsername() {
        return username;
    }
    
    public String getEmail() {
        return email;
    }
    
    public List<String> getRealmRoles() {
        return realmRoles;
    }
    
    public MultivaluedMap<String, String> getClientRoles() {
        return clientRoles;
    }
    
    public List<String> getScopes() {
        return scopes;
    }
    
    public boolean isAuthenticated() {
        return authenticated;
    }
    
    public Map<String, Object> getClaims() {
        return claims;
    }
    
    public String getRawToken() {
        return rawToken;
    }
}
