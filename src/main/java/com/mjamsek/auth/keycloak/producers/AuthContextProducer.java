package com.mjamsek.auth.keycloak.producers;

import com.mjamsek.auth.keycloak.models.AuthContext;
import com.mjamsek.auth.keycloak.services.AuthService;

import javax.enterprise.context.RequestScoped;
import javax.enterprise.inject.Produces;
import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.Context;

@RequestScoped
public class AuthContextProducer {
    
    @Context
    private HttpServletRequest request;
    
    @Inject
    private AuthService authService;
    
    @Produces
    @RequestScoped
    public AuthContext produceAuthContext() {
        String rawToken = request.getHeader("Authorization");
        return authService.produceContext(rawToken);
    }
}
