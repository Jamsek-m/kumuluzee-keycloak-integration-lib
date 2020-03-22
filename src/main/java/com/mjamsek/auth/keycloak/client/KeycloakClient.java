package com.mjamsek.auth.keycloak.client;

import com.mjamsek.auth.keycloak.apis.KeycloakApi;
import com.mjamsek.auth.keycloak.config.KeycloakConfig;
import com.mjamsek.auth.keycloak.exceptions.KeycloakCallException;
import com.mjamsek.auth.keycloak.exceptions.KeycloakConfigException;
import com.mjamsek.auth.keycloak.models.TokenResponse;
import com.mjamsek.auth.keycloak.payload.KeycloakJsonWebToken;
import org.eclipse.microprofile.rest.client.RestClientBuilder;
import org.keycloak.common.VerificationException;

import java.net.URI;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;
import java.util.logging.Level;
import java.util.logging.Logger;

@SuppressWarnings("unused")
public class KeycloakClient {
    
    private static final Logger log = Logger.getLogger(KeycloakClient.class.getName());
    
    private static final AtomicReference<TokenRepresentation> tokenCache = new AtomicReference<>();
    
    /**
     * Method for performing service calls to Keycloak server
     *
     * @param func function that will perform service call. Receives one argument - raw service token
     * @param <T>  Return type of service call response
     * @return response of service call
     * @throws KeycloakCallException on failed service call
     */
    public static <T> T callKeycloak(Function<String, T> func) throws KeycloakCallException {
        // if no token present, retrieve one, otherwise used cached one
        if (tokenCache.get() == null) {
            log.fine("Client has no previous service token, retrieving new one.");
            tokenCache.set(getServiceToken());
        }
        // if token is expired
        KeycloakJsonWebToken jsonWebToken = tokenCache.get().parsedToken;
        if (!jsonWebToken.isActive(KeycloakConfig.getInstance().getLeeway())) {
            log.fine("Stored service token is expired, retrieving new one.");
            tokenCache.set(getServiceToken());
        }
        
        // call requested function
        try {
            return func.apply(tokenCache.get().rawToken);
        } catch (Exception e) {
            throw new KeycloakCallException("Error performing service call!", e);
        }
    }
    
    private static TokenRepresentation getServiceToken() throws KeycloakCallException {
        if (KeycloakConfig.getInstance().getClientSecret() == null) {
            log.severe("Client secret not provided, cannot perform service call!");
            throw new KeycloakConfigException("Client secret not provided!");
        }
        
        try {
            KeycloakApi api = RestClientBuilder
                .newBuilder()
                .baseUri(URI.create(KeycloakConfig.getInstance().getAuthUrl()))
                .build(KeycloakApi.class);
            
            TokenResponse response = api.getServiceToken(
                KeycloakConfig.getInstance().getRealm(),
                KeycloakConfig.ServiceCall.getAuthHeader(),
                KeycloakConfig.ServiceCall.getFormData()
            );
            log.log(Level.INFO, "Retrieved service token for confidential client ''{0}''", KeycloakConfig.getInstance().getClientId());
            
            return new TokenRepresentation(response.getAccessToken());
        } catch (KeycloakCallException e) {
            log.severe(e.getMessage());
            throw e;
        } catch (VerificationException e) {
            log.severe(e.getMessage());
            throw new KeycloakCallException("Error verifying received service token!", e);
        }
    }
    
    static class TokenRepresentation {
        String rawToken;
        KeycloakJsonWebToken parsedToken;
        
        TokenRepresentation(String token) throws VerificationException {
            this.rawToken = token;
            this.parsedToken = KeycloakConfig.getInstance().getVerifier().verifyToken(token, KeycloakJsonWebToken.class);
        }
    }
}
