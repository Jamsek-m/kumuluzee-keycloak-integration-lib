package com.mjamsek.auth.keycloak.services;

import com.mjamsek.auth.keycloak.config.KeycloakConfig;
import com.mjamsek.auth.keycloak.exceptions.KeycloakException;
import com.mjamsek.auth.keycloak.models.KeycloakApi;
import com.mjamsek.auth.keycloak.models.TokenResponse;
import org.eclipse.microprofile.rest.client.RestClientBuilder;

import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Response;
import java.net.URI;
import java.util.function.Function;
import java.util.logging.Level;
import java.util.logging.Logger;

public class KeycloakClient {
    
    private static final Logger log = Logger.getLogger(KeycloakClient.class.getName());
    
    private static String accessToken = null;
    private static KeycloakApi apiInstance = null;
    
    /**
     * Method for performing service calls to Keycloak server
     * @param func code that will perform service call
     * @param <T> Return type of service call
     * @return result of service call
     * @throws KeycloakException on failed service call
     */
    public static <T> T callKeycloak(Function<String, T> func) throws KeycloakException {
        // if no token present, retrieve one, otherwise used cached one
        if (accessToken == null) {
            getServiceToken();
        }
        
        try {
            // call requested function
            return func.apply(accessToken);
        } catch (WebApplicationException e) {
            if (e.getResponse().getStatus() == Response.Status.UNAUTHORIZED.getStatusCode()) {
                // failed due to old token
                getServiceToken();
                try {
                    // retry call with newly gathered token
                    return func.apply(accessToken);
                } catch (WebApplicationException e2) {
                    // failed call for other reasons
                    e2.printStackTrace();
                    throw new KeycloakException(e2);
                }
            } else {
                // failed call for other reasons
                e.printStackTrace();
                throw new KeycloakException(e);
            }
        }
    }
    
    private static KeycloakApi getApi() {
        if (apiInstance == null) {
            apiInstance = RestClientBuilder.newBuilder().baseUri(URI.create(KeycloakConfig.get().getAuthUrl()))
                .build(KeycloakApi.class);
        }
        return apiInstance;
    }
    
    private static String getServiceToken() {
        if (KeycloakConfig.get().getService() != null) {
            try {
                TokenResponse response = getApi().getServiceToken(KeycloakConfig.get().getRealm(), KeycloakConfig.get().getService().getAuthHeader(), KeycloakConfig.get().getService().getFormData());
                log.log(Level.INFO, "Retrieved service token for client '{0}'", KeycloakConfig.get().getClientId());
                accessToken = response.getAccessToken();
                return response.getAccessToken();
            } catch (WebApplicationException e) {
                e.printStackTrace();
                return null;
            }
        }
        log.severe("Cannot retrieve service token! Client must be confidental and its secret must be provided in configuration!");
        return null;
    }
    
}
