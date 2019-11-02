package com.mjamsek.auth.keycloak.config;

import com.kumuluz.ee.configuration.utils.ConfigurationUtil;
import com.mjamsek.auth.keycloak.models.KeycloakApi;
import org.eclipse.microprofile.rest.client.RestClientBuilder;

import javax.json.JsonArray;
import javax.json.JsonObject;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Form;
import java.math.BigInteger;
import java.net.URI;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BiConsumer;
import java.util.logging.Logger;

public class KeycloakConfig {
    
    private static final Logger log = Logger.getLogger(KeycloakConfig.class.getName());
    
    private static KeycloakConfig instance;
    
    private String realm;
    private String authUrl;
    private String clientId;
    private String clientSecret;
    private Service service;
    private Key publicKey;
    
    public static void initialize() {
        if (instance == null) {
            ConfigurationUtil configurationUtil = ConfigurationUtil.getInstance();
            instance = new KeycloakConfig();
            instance.realm = configurationUtil.get("kc.realm").orElseThrow(() -> new RuntimeException("Missing config!"));
            instance.authUrl = configurationUtil.get("kc.auth-server-url").orElseThrow(() -> new RuntimeException("Missing config!"));
            instance.clientId = configurationUtil.get("kc.client-id").orElseThrow(() -> new RuntimeException("Missing config!"));
            instance.clientSecret = configurationUtil.get("kc.auth.client-secret").orElse(null);
            if (instance.clientSecret != null) {
                instance.service = new Service();
                instance.service.setAuthHeader(instance.clientId, instance.clientSecret);
            }
            retrievePublicKey();
        }
    }
    
    public static KeycloakConfig get() {
        return instance;
    }
    
    private static void retrievePublicKey() {
        KeycloakApi keycloakApi = RestClientBuilder.newBuilder().baseUri(URI.create(instance.authUrl))
            .build(KeycloakApi.class);
    
        final AtomicReference<Throwable> throwable = new AtomicReference<>();
        
        BiConsumer<JsonObject, Throwable> asyncCallback = (jsonResponse, err) -> {
            if (err != null) {
                log.severe(err.getMessage());
                throwable.set(err);
            }
    
            JsonArray keys = jsonResponse.getJsonArray("keys");
            JsonObject certConfig = keys.getJsonObject(0);
    
            String kid = certConfig.getString("kid");
            String modulusStr = certConfig.getString("n");
            String exponentStr = certConfig.getString("e");
    
            BigInteger modulus = new BigInteger(1, base64Decode(modulusStr));
            BigInteger publicExponent = new BigInteger(1, base64Decode(exponentStr));
    
            Key key = new Key();
            key.kid = kid;
            key.modulus = modulus;
            key.exponent = publicExponent;
            instance.publicKey = key;
            log.info("Retrieved public key from Keycloak server");
        };
    
        try {
            keycloakApi.getCertsAsync(instance.realm).whenCompleteAsync(asyncCallback);
        } catch (Throwable t) {
            t.printStackTrace();
            throw new WebApplicationException(t, 500);
        }
        
        if (throwable.get() != null) {
            throwable.get().printStackTrace();
            throw new WebApplicationException(throwable.get(), 500);
        }
    }
    
    private static byte[] base64Decode(String base64) {
        base64 = base64.replaceAll("-", "+");
        base64 = base64.replaceAll("_", "/");
        switch (base64.length() % 4) // Pad with trailing '='s
        {
            case 0:
                break; // No pad chars in this case
            case 2:
                base64 += "==";
                break; // Two pad chars
            case 3:
                base64 += "=";
                break; // One pad char
            default:
                throw new RuntimeException(
                    "Illegal base64url string!");
        }
        return Base64.getDecoder().decode(base64);
    }
    
    public String getRealm() {
        return realm;
    }
    
    public String getAuthUrl() {
        return authUrl;
    }
    
    public String getClientId() {
        return clientId;
    }
    
    public Key getPublicKey() {
        return publicKey;
    }
    
    public String getClientSecret() {
        return clientSecret;
    }
    
    public Service getService() {
        return service;
    }
    
    public PublicKey createPublicKey(String keyId) {
        if (this.publicKey == null) {
            throw new RuntimeException("Cannot create public key! Public key was not retrieved from server!");
        }
        if (keyId.equals(this.publicKey.kid)) {
            try {
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                return keyFactory.generatePublic(new RSAPublicKeySpec(this.publicKey.modulus, this.publicKey.exponent));
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                e.printStackTrace();
                throw new RuntimeException("Error creating key!");
            }
        } else {
            throw new RuntimeException("KID doesn't match!");
        }
    }
    
    public static class Key {
        private String kid;
        private BigInteger modulus;
        private BigInteger exponent;
    
        public String getKid() {
            return kid;
        }
    
        public BigInteger getModulus() {
            return modulus;
        }
    
        public BigInteger getExponent() {
            return exponent;
        }
    }
    
    public static class Service {
        private String authHeader;
        private Form formData;
        
        public Service(){
            this.formData = new Form();
            this.formData.param("grant_type", "client_credentials");
        }
        
        public void setAuthHeader(String clientId, String clientSecret) {
            String credentials = clientId + ":" + clientSecret;
            String credentialsEncoded = new String(Base64.getEncoder().encode(credentials.getBytes()));
            this.authHeader = "Basic " + credentialsEncoded;
        }
    
        public Form getFormData() {
            return formData;
        }
    
        public String getAuthHeader() {
            return authHeader;
        }
    }
}
