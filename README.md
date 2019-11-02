# KumuluzEE Keycloak integration library

[![GitHub release (latest SemVer)](https://img.shields.io/github/v/release/Jamsek-m/kumuluzee-keycloak-integration-lib)](https://github.com/Jamsek-m/kumuluzee-keycloak-integration-lib/releases)
![Build Status](https://jenkins.mjamsek.com/buildStatus/icon?job=kumuluzee-keycloak-integration-lib)
[![GitHub license](https://img.shields.io/github/license/Jamsek-m/kumuluzee-keycloak-integration-lib)](https://github.com/Jamsek-m/kumuluzee-keycloak-integration-lib/blob/master/LICENSE)

> Library for integration of Keycloak authentication with KumuluzEE framework

## Requirements

Library is compatible with Java 11+ and Keycloak 7.0.0+

## Usage

Import library in your project:
```xml
<dependency>
    <groupId>com.mjamsek.auth</groupId>
    <artifactId>kumuluzee-keycloak-integration-lib</artifactId>
    <version>${kumuluee-keycloak-lib.version}</version>
</dependency>
``` 

Provide keycloak values in `config.yml`:

```yaml
kc:
  # Mandatory options:
  realm: keycloak-realm
  auth-server-url: https://keycloak.example.com/auth
  client-id: keycloak-client
  # If this is confidential client, you need to provide client secret
  auth:
    client-secret: <client_secret>
  # Mapping from JWT to AuthContextObject 
  claims:
    username: preferred_username
    email: email
```

### Authentication and authorization

To enable security in resource class, you must annotate it with `@SecureResource`. Then you can annotate methods in this class with appropriate annotations. You can also put annotations on class. This means that non-annotated methods will take class-based access level.

```java
// enable security in this class
@SecureResource
// all methods need user to be authenticated (optional, you can put annotations on method only)
@AuthenticatedAllowed
@RequestScoped
@Path("/customers")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class SampleResource {

    @GET
    // only admins or salesmen can retrieve list of customers
    @RealmRolesAllowed({"salesman", "admin"})
    public Response getCustomers() {
        // ... 
        return Response.ok(customers).build();
    }
    
    @GET
    // This method uses class annotated access level - authentication only
    public Response getCustomerDetails() {
        // ... 
        return Response.ok(customerDetails).build();
    }

    @POST
    // This method overrides class based annotation and is public - no authentication needed
    @PublicResource
    public Response notifyCustomer() {
        // ... 
        return Response.ok().build();
    }

}
```

If you want to expose single method in otherwise protected resource class you can use `@PublicResource` annotation on method, you want to make public.

#### Annotation types:

* `@AuthenticatedAllowed`: to access this method a user must present valid JWT
* `@RolesAllowed({"dev"})`: to access this method a user must have role 'dev'
* `@RealmRolesAllowed({"dev"})`: to access this method a user must have **realm** role 'dev'
* `@ClientRolesAllowed(client = "keycloak-client", roles = {"dev"})`: to access this method a user must have **client** role 'dev' on client 'kecloak-client'.
* `@ScopesAllowed({"read:messages"})`: to access this method a user must have scope 'read:messages'

### Security context

You can retrieve data about user trying to access endpoint by injecting `AuthContext` object:

```java
@Inject
private AuthContext authContext;
```

In unsecured (public) endpoints, authContext will not be available. Therefore it is good practice to check if user is authenticated before using its methods:
```java
if (authContext.isAuthenticated()) {
    // ...
}
``` 

Auth context provides following data: 

* user id *(token subject)*
* username
* email
* realm roles
* client roles
* scopes

### Keycloak client

Library also provides client to perform service calls to keycloak server.

To use it, configuration key `kc.auth.client-secret` must be provided. Additionally, configured client must be **confidential** and service account must be **enabled** (with appropriate roles assigned).

When you have configured service properly, you can call keycloak using `KeycloakClient` class:

```java
KeycloakClient.callKeycloak((token) -> {
    // perform http call to keycloak using token variable as credential
});
```

`callKeycloak` method accepts lambda function with one string parameter. This parameter is set by keycloak client to service token, which it is able to retrieve on its own using client secret we provided.

Library requires `kumuluzee-rest-client` dependency to be provided at runtime. It is therefore very advisable that you use rest client  yourself when using callKeycloak function.

```java
// KeycloakAPI.java
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public interface KeycloakAPI {
   
    @GET
    @Path("/admin/realms/{realm}/users")
    List<Account> getAccounts(
        @PathParam("realm") String realm,
        @HeaderParam("Authorization") String authorizationHeader
    );
}
``` 

```java
// AccountService.java
public class AccountService {

    public List<Account> getAccountsFromKeycloak() {
        KeycloakAPI api = RestClientBuilder
            .newBuilder()
            .baseUri(URI.create(KeycloakConfig.get().getAuthUrl()))
            .build(KeycloakAPI.class);

        List<Account> accounts = KeycloakClient.callKeycloak((token) -> {
            return api.getAccounts(
                KeycloakConfig.get().getRealm(),
                "Bearer " + token
            );
        });
        return accounts;
    }
}
```

## Changelog

Changes can be viewed on [releases page](https://github.com/Jamsek-m/kumuluzee-keycloak-integration-lib/releases) on GitHub.

## License

MIT
