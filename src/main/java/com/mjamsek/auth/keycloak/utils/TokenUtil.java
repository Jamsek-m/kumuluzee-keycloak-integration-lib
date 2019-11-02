package com.mjamsek.auth.keycloak.utils;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mjamsek.auth.keycloak.config.KeycloakConfig;
import org.keycloak.TokenVerifier;
import org.keycloak.common.VerificationException;
import org.keycloak.representations.JsonWebToken;

import java.io.IOException;
import java.security.PublicKey;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class TokenUtil {
    
    private static final Pattern JWT_REGEX = Pattern.compile("^[A-Za-z0-9-_=]+\\.[A-Za-z0-9-_=]+\\.[A-Za-z0-9-_.+/=]+$");
    
    @SuppressWarnings("unchecked")
    public static JsonWebToken verifyToken(String token) throws VerificationException {
        
        String keyId = getKeyId(token);
        PublicKey publicKey = KeycloakConfig.get().createPublicKey(keyId);
    
        TokenVerifier verifier = TokenVerifier.create(token, JsonWebToken.class)
            .withChecks(TokenVerifier.SUBJECT_EXISTS_CHECK, TokenVerifier.IS_ACTIVE)
            .publicKey(publicKey);
    
        return verifier.verify().getToken();
    }
    
    private static String getKeyId(String token) throws VerificationException {
    
        Matcher matcher = JWT_REGEX.matcher(token);
        if (!matcher.find()) {
            throw new VerificationException("Malformed token!");
        }
        
        String tokenHeader = token.split("\\.")[0];
        tokenHeader = new String(Base64.getDecoder().decode(tokenHeader.getBytes()));
        try {
            ObjectMapper mapper = new ObjectMapper();
            JsonNode json = mapper.readTree(tokenHeader);
            return json.get("kid").textValue();
        } catch (IOException e) {
            e.printStackTrace();
            throw new VerificationException("Malformed token!");
        }
    }
    
}
