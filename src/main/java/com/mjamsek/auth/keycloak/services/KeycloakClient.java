package com.mjamsek.auth.keycloak.services;

import com.mjamsek.auth.keycloak.config.KeycloakConfig;
import com.mjamsek.auth.keycloak.exceptions.KeycloakException;
import com.mjamsek.auth.keycloak.models.KeycloakApi;
import com.mjamsek.auth.keycloak.models.ServiceCallBeanParam;
import com.mjamsek.auth.keycloak.models.TokenResponse;
import com.mjamsek.auth.keycloak.payload.KeycloakJsonWebToken;
import org.eclipse.microprofile.rest.client.RestClientBuilder;
import org.keycloak.common.VerificationException;

import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Response;
import java.net.URI;
import java.util.function.Function;
import java.util.logging.Level;
import java.util.logging.Logger;

public class KeycloakClient {
    
    private static final Logger log = Logger.getLogger(KeycloakClient.class.getName());
    
    private static TokenRepresentation tokenRepresentation = null;
    private static KeycloakApi apiInstance = null;
    
    /**
     * Method for performing service calls to Keycloak server
     *
     * @param func code that will perform service call
     * @param <T>  Return type of service call
     * @return result of service call
     * @throws KeycloakException on failed service call
     */
    public static <T> T callKeycloak(Function<String, T> func) throws KeycloakException {
        // if no token present, retrieve one, otherwise used cached one
        if (tokenRepresentation == null) {
            log.fine("Client has no previous token, retrieving new one.");
            getServiceToken();
        }
        // if token is expired
        if (!tokenRepresentation.parsedToken.isActive(KeycloakConfig.getInstance().getLeeway())) {
            log.fine("Stored token is expired, retrieving new one.");
            getServiceToken();
        }
        
        try {
            // call requested function
            return func.apply(tokenRepresentation.rawToken);
        } catch (WebApplicationException e) {
            e.printStackTrace();
            throw new KeycloakException(e);
            
            /*if (e.getResponse().getStatus() == Response.Status.UNAUTHORIZED.getStatusCode()) {
                // failed due to old token
                getServiceToken();
                try {
                    // retry call with newly gathered token
                    return func.apply(tokenRepresentation.rawToken);
                } catch (WebApplicationException e2) {
                    // failed call for other reasons
                    e2.printStackTrace();
                    throw new KeycloakException(e2);
                }
            } else {
                // failed call for other reasons
                e.printStackTrace();
                throw new KeycloakException(e);
            }*/
        }
    }
    
    private static KeycloakApi getApi() {
        if (apiInstance == null) {
            apiInstance = RestClientBuilder
                .newBuilder()
                .baseUri(URI.create(KeycloakConfig.getInstance().getAuthUrl()))
                .build(KeycloakApi.class);
        }
        return apiInstance;
    }
    
    private static TokenRepresentation getServiceToken() {
        if (KeycloakConfig.getInstance().getClientSecret() == null) {
            log.severe("Client secret not provided, cannot perform service call!");
            throw new RuntimeException("Client secret not provided!");
        }
        
        try {
            ServiceCallBeanParam params = new ServiceCallBeanParam();
            params.setAuthorizationHeader(KeycloakConfig.ServiceCall.getAuthHeader());
            params.setRealm(KeycloakConfig.getInstance().getRealm());
            
            TokenResponse response = getApi().getServiceToken(params, KeycloakConfig.ServiceCall.getFormData());
            log.log(Level.INFO, "Retrieved service token for client '{0}'", KeycloakConfig.getInstance().getClientId());
            
            tokenRepresentation = new TokenRepresentation(response.getAccessToken());
            return tokenRepresentation;
        } catch (WebApplicationException | VerificationException e) {
            e.printStackTrace();
            return null;
        }
    }
    
    public static class TokenRepresentation {
        private String rawToken;
        private KeycloakJsonWebToken parsedToken;
        
        public TokenRepresentation(String token) throws VerificationException {
            this.rawToken = token;
            this.parsedToken = KeycloakConfig.getInstance().getVerifier().verifyToken(token, KeycloakJsonWebToken.class);
        }
        
        public String getRawToken() {
            return rawToken;
        }
        
        public KeycloakJsonWebToken getParsedToken() {
            return parsedToken;
        }
    }
    
}
