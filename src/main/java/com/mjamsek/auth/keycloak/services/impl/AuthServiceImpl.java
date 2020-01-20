package com.mjamsek.auth.keycloak.services.impl;

import com.mjamsek.auth.keycloak.annotations.*;
import com.mjamsek.auth.keycloak.config.KeycloakConfig;
import com.mjamsek.auth.keycloak.models.AuthContext;
import com.mjamsek.auth.keycloak.payload.KeycloakJsonWebToken;
import com.mjamsek.auth.keycloak.services.AuthService;
import com.mjamsek.auth.keycloak.utils.AnnotationResult;
import com.mjamsek.auth.keycloak.utils.AnnotationUtil;
import org.keycloak.common.VerificationException;

import javax.enterprise.context.RequestScoped;
import javax.inject.Inject;
import javax.interceptor.InvocationContext;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.ForbiddenException;
import javax.ws.rs.NotAuthorizedException;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MultivaluedHashMap;
import javax.ws.rs.core.Response;
import java.lang.reflect.Method;
import java.util.*;

@RequestScoped
public class AuthServiceImpl implements AuthService {
    
    @Context
    private HttpServletRequest request;
    
    @Inject
    private AuthContext authContext;
    
    @Override
    public void processSecurity(InvocationContext context) {
        
        AnnotationResult<RolesAllowed> rolesAllowed = AnnotationUtil.getRolesAllowedAnnotation(context.getMethod());
        if (rolesAllowed.hasAnnotation()) {
            if (this.isNotPublic(rolesAllowed, context.getMethod())) {
                this.validateRoles(rolesAllowed.getAnnotation().value());
            }
        } else {
            AnnotationResult<RealmRolesAllowed> realmRolesAllowed = AnnotationUtil
                .getRealmRolesAllowedAnnotation(context.getMethod());
            if (realmRolesAllowed.hasAnnotation()) {
                if (this.isNotPublic(realmRolesAllowed, context.getMethod())) {
                    this.validateRealmRoles(realmRolesAllowed.getAnnotation().value());
                }
            } else {
                AnnotationResult<ClientRolesAllowed> clientRolesAllowed = AnnotationUtil
                    .getClientRolesAllowedAnnotation(context.getMethod());
                if (clientRolesAllowed.hasAnnotation()) {
                    ClientRolesAllowed clientRolesAllowedAnnotation = clientRolesAllowed.getAnnotation();
                    if (this.isNotPublic(clientRolesAllowed, context.getMethod())) {
                        this.validateClientRoles(
                            clientRolesAllowedAnnotation.client(),
                            clientRolesAllowedAnnotation.roles()
                        );
                    }
                } else {
                    AnnotationResult<ScopesAllowed> scopesAllowed = AnnotationUtil.getScopesAllowedAnnotation(context.getMethod());
                    if (scopesAllowed.hasAnnotation()) {
                        ScopesAllowed scopesAllowedAnnotation = scopesAllowed.getAnnotation();
                        if (this.isNotPublic(scopesAllowed, context.getMethod())) {
                            this.validateScopes(scopesAllowedAnnotation.value());
                        }
                    } else {
                        AnnotationResult<AuthenticatedAllowed> authenticatedAllowed = AnnotationUtil
                            .getAuthenticatedAllowedAnnotation(context.getMethod());
                        if (authenticatedAllowed.hasAnnotation()) {
                            if (this.isNotPublic(authenticatedAllowed, context.getMethod())) {
                                this.validateAuthenticated();
                            }
                        }
                    }
                }
            }
        }
    }
    
    @Override
    public AuthContext produceContext(String rawToken) {
        if (rawToken == null) {
            return AuthContext.empty();
        }
        if (rawToken.startsWith("Bearer")) {
            rawToken = rawToken.replace("Bearer ", "");
        }
        
        try {
            KeycloakJsonWebToken token = KeycloakConfig.getInstance().getVerifier().verifyToken(rawToken, KeycloakJsonWebToken.class);
            
            AuthContext authContext = new AuthContext();
            authContext.setAuthenticated(true);
            
            authContext.setId(token.getSubject());
            
            authContext.setUsername(token.getPreferredUsername());
            authContext.setEmail(token.getEmail());
            
            String scopes = token.getScopes();
            authContext.setScopes(Arrays.asList(scopes.split(" ")));
            
            List<String> realmRoles = token.getRealmAccess().getRoles();
            authContext.setRealmRoles(realmRoles);
            
            authContext.setClientRoles(new MultivaluedHashMap<>());
            Map<String, KeycloakJsonWebToken.Roles> clientRolesMap = token.getResourceAccess();
            clientRolesMap.keySet().forEach(clientId -> authContext.getClientRoles().addAll(clientId, clientRolesMap.get(clientId).getRoles()));
            
            return authContext;
        } catch (VerificationException e) {
            return AuthContext.empty();
        }
    }
    
    /**
     * Returns true if method is not explicitly public resource.
     *
     * @param annotation annotation to be checked
     * @param method     executing method
     * @param <T>        auth annotation type
     * @return true if method is not public
     */
    private <T> boolean isNotPublic(AnnotationResult<T> annotation, Method method) {
        if (annotation.isClassAnnotated()) {
            PublicResource publicResource = method.getDeclaredAnnotation(PublicResource.class);
            return publicResource == null;
        }
        return true;
    }
    
    private void validateAuthenticated() throws NotAuthorizedException {
        if (!authContext.isAuthenticated()) {
            throw new NotAuthorizedException(Response.status(Response.Status.UNAUTHORIZED).build());
        }
    }
    
    private void validateRealmRoles(String[] requiredRoles) throws NotAuthorizedException, ForbiddenException {
        this.validateAuthenticated();
        
        boolean hasRole = Set.of(requiredRoles).stream().anyMatch(role -> authContext.hasRealmRole(role));
        
        if (!hasRole) {
            throw new ForbiddenException(Response.status(Response.Status.FORBIDDEN).build());
        }
    }
    
    private void validateClientRoles(String clientId, String[] clientRoles) throws NotAuthorizedException, ForbiddenException {
        this.validateAuthenticated();
        
        boolean hasRole = Set.of(clientRoles).stream().anyMatch(role -> authContext.hasClientRole(clientId, role));
        
        if (!hasRole) {
            throw new ForbiddenException(Response.status(Response.Status.FORBIDDEN).build());
        }
    }
    
    private void validateRoles(String[] roles) throws NotAuthorizedException, ForbiddenException {
        this.validateAuthenticated();
        boolean realmRoleFound = false;
        boolean clientRoleFound = false;
        try {
            this.validateRealmRoles(roles);
            realmRoleFound = true;
        } catch (ForbiddenException ignored) {
        }
        for (String clientId : authContext.getClientRoles().keySet()) {
            try {
                this.validateClientRoles(clientId, roles);
                clientRoleFound = true;
            } catch (ForbiddenException ignored) {
            }
        }
        
        if (!realmRoleFound && !clientRoleFound) {
            throw new ForbiddenException(Response.status(Response.Status.FORBIDDEN).build());
        }
    }
    
    private void validateScopes(String[] requiredScopes) throws NotAuthorizedException, ForbiddenException {
        this.validateAuthenticated();
        
        boolean hasScope = Set.of(requiredScopes).stream().anyMatch(scope -> authContext.hasScope(scope));
        
        if (!hasScope) {
            throw new ForbiddenException(Response.status(Response.Status.FORBIDDEN).build());
        }
    }
}
