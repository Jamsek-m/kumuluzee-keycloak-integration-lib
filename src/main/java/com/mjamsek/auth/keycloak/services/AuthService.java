package com.mjamsek.auth.keycloak.services;

import javax.interceptor.InvocationContext;

public interface AuthService {
    
    void processSecurity(InvocationContext context);
    
}
