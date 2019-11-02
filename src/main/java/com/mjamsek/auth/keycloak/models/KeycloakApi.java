package com.mjamsek.auth.keycloak.models;

import javax.json.JsonObject;
import javax.ws.rs.*;
import javax.ws.rs.core.Form;
import javax.ws.rs.core.MediaType;
import java.util.concurrent.CompletionStage;

@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public interface KeycloakApi {
    
    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    @Path("/realms/{realm}/protocol/openid-connect/token")
    TokenResponse getServiceToken(
        @PathParam("realm") String realm,
        @HeaderParam("Authorization") String authorizationHeader,
        Form form
    );
    
    @GET
    @Path("/realms/{realm}/protocol/openid-connect/certs")
    JsonObject getCerts(@PathParam("realm") String realm);
    
    @GET
    @Path("/realms/{realm}/protocol/openid-connect/certs")
    CompletionStage<JsonObject> getCertsAsync(@PathParam("realm") String realm);
    
}
