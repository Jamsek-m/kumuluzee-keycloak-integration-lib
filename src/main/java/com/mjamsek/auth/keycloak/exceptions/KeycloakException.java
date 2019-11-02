package com.mjamsek.auth.keycloak.exceptions;

import javax.ws.rs.WebApplicationException;

public class KeycloakException extends RuntimeException {
    
    public KeycloakException(String message) {
        super(message);
    }
    
    public KeycloakException(WebApplicationException e) {
        super(String.format("Error when calling Keycloak API. Status: %d. Message: %s", e.getResponse().getStatus(), e.getMessage()));
    }
    
}
