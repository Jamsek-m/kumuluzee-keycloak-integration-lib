package com.mjamsek.auth.keycloak.producers;

import com.kumuluz.ee.configuration.utils.ConfigurationUtil;
import com.mjamsek.auth.keycloak.models.AuthContext;
import com.mjamsek.auth.keycloak.utils.TokenUtil;
import org.keycloak.common.VerificationException;
import org.keycloak.representations.JsonWebToken;

import javax.enterprise.context.RequestScoped;
import javax.enterprise.inject.Produces;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MultivaluedHashMap;
import java.util.*;

@RequestScoped
public class AuthContextProducer {
    
    @Context
    private HttpServletRequest request;
    
    @SuppressWarnings("unchecked")
    @Produces
    @RequestScoped
    public AuthContext produceAuthContext() {
        
        String rawToken = request.getHeader("Authorization");
        if (rawToken == null) {
            return AuthContext.empty();
        }
        if (rawToken.startsWith("Bearer")) {
            rawToken = rawToken.replace("Bearer ", "");
        }
    
        try {
            JsonWebToken token = TokenUtil.verifyToken(rawToken);
            
            AuthContext authContext = new AuthContext();
            authContext.setAuthenticated(true);
            
            authContext.setId(token.getSubject());
            String usernameClaimName = ConfigurationUtil.getInstance().get("kc.claims.username").orElse("preferred_username");
            authContext.setUsername((String) token.getOtherClaims().getOrDefault(usernameClaimName, ""));
            String emailClaimName = ConfigurationUtil.getInstance().get("kc.claims.email").orElse("email");
            authContext.setEmail((String) token.getOtherClaims().getOrDefault(emailClaimName, ""));
            
            String scopes = (String) token.getOtherClaims().getOrDefault("scope", "");
            authContext.setScopes(Arrays.asList(scopes.split(" ")));
            
            Map<String, List<String>> realmAccess = (Map<String, List<String>>) token.getOtherClaims().getOrDefault("realm_access", new ArrayList());
            List<String> realmRoles = realmAccess.getOrDefault("roles", new ArrayList<>());
            authContext.setRealmRoles(realmRoles);
            
            Map<String, Map<String, List<String>>> resourceAccess = (Map<String, Map<String, List<String>>>) token.getOtherClaims().getOrDefault("resource_access", new HashMap<>());
            authContext.setClientRoles(new MultivaluedHashMap<>());
            resourceAccess.keySet().forEach(clientId -> {
                Map<String, List<String>> clientAccess = resourceAccess.get(clientId);
                List<String> clientRoles = clientAccess.getOrDefault("roles", new ArrayList<>());
                authContext.getClientRoles().addAll(clientId, clientRoles);
            });
            
            return authContext;
        } catch (VerificationException e) {
            return AuthContext.empty();
        }
    }
}
