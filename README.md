# Building a Google OAuth Connector with Quarkus: Secure Token Management and Refresh
You know how it goes: when you're building apps that need to talk to Google APIs, OAuth is that unavoidable beast. You've got to juggle access tokens, handle refreshes when they expire, and store them securely—without starting from zero every time. It's frustrating, right? Time-sucking, prone to bugs, and not a lot of fun.

In this post, I'll walk you through whipping up a quick Quarkus service that hooks into Google accounts with OIDC. It stores access and refresh tokens in PostgreSQL using Hibernate Reactive Panache, and gives you endpoints to fetch or refresh them on the fly. If you're tinkering with email automation, calendar syncs, or anything Google-powered, this setup will save you headaches and get your token management a breeze.

**Note:** This post has been inspired by [Markus Eisele's](https://substack.com/@myfear) excellent article, "[How to Add “Sign in with Google” to Your Quarkus App](https://substack.com/home/post/p-176115942)." If you're not already subscribed to his Substack, I highly recommend it for valuable insights.

The full source code of this article is available [here](https://github.com/fmatar/quarkus-google-connect)

Now first things first, let's get to the good stuff: prerequisites and setup.

### Prerequisites and Setup

Before we jump into the code, let's make sure you've got everything ready. This service is built on Quarkus 3.28.5 (as of this writing—check for updates if you're reading later), so you'll need Java 21 and Maven. If you're new to Quarkus, it's worth a quick spin through their getting-started guide, but we'll cover the essentials here.

### What You'll Need

- **Java and Maven:** JDK 21 (I'm using OpenJDK) and Maven 3.8+.
- **PostgreSQL:** For local dev, Quarkus Dev Services spins up a container automatically—no install needed. For prod, have a DB instance handy.
- **Google Developer Console Setup:** Head to console.developers.google.com, create a project, enable OAuth 2.0 credentials (Web application type), and note your Client ID and Secret. Set the redirect URI to http://localhost:8080/callback for testing.
- **Environment Variables:** Export OIDC_GOOGLE_CLIENT_ID and OIDC_GOOGLE_CLIENT_SECRET in your terminal or set them in an `.env` file

### Project Initialization

Start by creating a new Quarkus project. You can use the Quarkus CLI or just Maven. Here's the command-line way:

```bash
mvn io.quarkus.platform:quarkus-maven-plugin:3.28.5:create \
    -DprojectGroupId=com.acme \
    -DprojectArtifactId=google-connector \
    -Dextensions=rest-jackson,oidc-client,hibernate-reactive-panache,reactive-pg-client,vertx
```

This pulls in the key extensions: REST for endpoints, OIDC Client for auth, Hibernate Reactive Panache for DB ops, Reactive PG Client for PostgreSQL, and Vertx for web client needs.

### Key Dependencies

Your pom.xml should look something like this (trimmed for brevity—full version in the repo):

```xml

<dependencies>
  <dependency>
    <groupId>io.quarkus</groupId>
    <artifactId>quarkus-rest-jackson</artifactId>
  </dependency>
  <dependency>
    <groupId>io.quarkus</groupId>
    <artifactId>quarkus-oidc-client</artifactId>
  </dependency>
  <dependency>
    <groupId>io.quarkus</groupId>
    <artifactId>quarkus-hibernate-reactive-panache</artifactId>
  </dependency>
  <dependency>
    <groupId>io.quarkus</groupId>
    <artifactId>quarkus-reactive-pg-client</artifactId>
  </dependency>
  <dependency>
    <groupId>io.quarkus</groupId>
    <artifactId>quarkus-vertx</artifactId>
  </dependency>
  <!-- Other deps like arc, rest-client-jackson, etc. -->
</dependencies>
```

### Configuration

Drop this into your `application.properties`

```text
# Google OIDC Client Configuration
quarkus.oidc-client.auth-server-url=https://accounts.google.com
quarkus.oidc-client.discovery-enabled=true
quarkus.oidc-client.client-id=${OIDC_GOOGLE_CLIENT_ID}
quarkus.oidc-client.credentials.secret=${OIDC_GOOGLE_CLIENT_SECRET}
quarkus.oidc-client.grant.type=code
quarkus.oidc-client.scopes=openid,email,profile

# Reactive Database Configuration (PostgreSQL)
quarkus.datasource.db-kind=postgresql
quarkus.datasource.devservices.db-name=google-connector-db
quarkus.datasource.devservices.port=5432
quarkus.datasource.username=admin
quarkus.datasource.password=admin
quarkus.hibernate-orm.schema-management.strategy=update
```

This sets up OIDC with Google (discovery auto-fetches endpoints) and a reactive Postgres connection. In dev mode, Quarkus handles the DB for you.

With that sorted, you're ready to build the core logic.

### Configuring Quarkus OIDC Client

Now that your project's set up, the first core piece is configuring the OIDC client in Quarkus to talk to Google's auth servers. Quarkus makes this a breeze with its quarkus-oidc-client extension—it handles token grants, discovery, and more under the hood, so you don't have to mess with low-level HTTP calls for everything.

We already touched on the basics in application.properties, but let's break it down. The config tells Quarkus to use Google's OIDC endpoints (auto-discovered via discovery-enabled=true), plugs in your client ID and secret from env vars, and specifies the grant type (code for authorization code flow, which is secure for server-side apps). Scopes like openid, email, profile get you the user's basic info and ID token.

Here's a quick recap of that config snippet for clarity:

```text
# Google OIDC Client Configuration
quarkus.oidc-client.auth-server-url=https://accounts.google.com
quarkus.oidc-client.discovery-enabled=true
quarkus.oidc-client.client-id=${OIDC_GOOGLE_CLIENT_ID}
quarkus.oidc-client.credentials.secret=${OIDC_GOOGLE_CLIENT_SECRET}
quarkus.oidc-client.grant.type=code
quarkus.oidc-client.scopes=openid,email,profile
```

**Why this matters:** Auto-discovery fetches the well-known configuration from Google, saving you from hardcoding endpoints that might change. The `grant.type=code`ensures we're using the auth code flow, which exchanges a code for tokens server-side—safer than implicit flow for public clients.

In your code, you'll inject the `OidcClient` bean (provided by Quarkus) to handle token exchanges later. No extra setup needed; Quarkus wires it up automatically.

With OIDC configured, we're ready to build the entry point for the auth flow.

### Building the Authorization Flow (/connect Endpoint)

With OIDC configured, the next step is kicking off the OAuth dance. Hitting http://localhost:8080/connect will redirect you directly to the Google authorization page.

The logic for generating the authorization URL is in `GoogleTokenManager.java`. We build the URL using `UriBuilder` from Jakarta EE, stuffing in params like client ID, redirect URI, scopes, and a random `state` for security (to prevent CSRF attacks).

Here's the key method in the token manager:

```java
  import io.smallrye.mutiny.Uni;
import jakarta.ws.rs.core.UriBuilder;

public Uni<String> connect() {
  return Uni.createFrom().item(() -> {
    var state = UUID.randomUUID().toString();
    var authUrl =
      UriBuilder.fromUri(AUTHORIZATION_ENDPOINT)
        .queryParam("client_id", clientId)
        .queryParam("redirect_uri", REDIRECT_URI)
        .queryParam("scope", "openid email profile")
        .queryParam("response_type", "code")
        .queryParam("access_type", "offline")
        .queryParam("prompt", "consent")
        .queryParam("state", state);
    return authUrl.build().toString();
  });
}
```

- state: A UUID to verify later in the callback—essential for security.
- access_type=offline: Gets you a refresh token, so you can renew access without re-authing.
- prompt=consent: Forces Google to ask for user consent, handy for testing or ensuring refresh tokens.
- We wrap it in Uni from Mutiny for reactive goodness—non-blocking and composable.

In `GoogleConnectResource.java`, we expose this as a GET endpoint that delegates to the `GoogleTokenManager`:

```java
@GET
@Path("connect")
@Produces(MediaType.TEXT_PLAIN)
public Uni<String> connect() {
    return tokenManager.connect();
}
```

Now, onto handling that callback.

### Handling the Callback and Token Storage

Once the user authenticates with Google, they get redirected to your `/callback` endpoint with an authorization code and state. This is where things get interesting: we exchange the code for access and refresh tokens, fetch user info, and stash everything in the database for later use. On success, returns the stored UserToken as JSON (including ID and email). On failure, returns a ServiceError JSON object.

The `handleCallback` method in `GoogleTokenManager.java` does the heavy lifting. It checks for the code, uses Quarkus's OidcClient to swap it for tokens (adding the redirect URI as an extra param), then calls `handleTokens` to process them. Error responses now use the `ServiceError` record for consistent error handling.

Key snippet:

```java
import com.acme.ServiceError;
import io.smallrye.mutiny.Uni;
import jakarta.ws.rs.core.Response;

public Uni<Response> handleCallback(String code, String state) {
  if (code==null) {
    return Uni.createFrom().item(
      Response.status(Response.Status.BAD_REQUEST)
        .entity(new ServiceError(Response.Status.BAD_REQUEST.getStatusCode(), "Missing code"))
        .build());
  }

  var extraParams = new HashMap<String, String>();
  extraParams.put("code", code);
  extraParams.put("redirect_uri", REDIRECT_URI);

  return oidcClient
    .getTokens(extraParams)
    .flatMap(tokens -> handleTokens(tokens, state))
    .onFailure().recoverWithItem(t ->
      Response.serverError().entity(new ServiceError(500, "Token exchange failed")).build());
}
```

The `handleTokens` method fires off a request to Google's userinfo endpoint with the access token to grab details like `sub` (unique ID) and email. Then it creates a `UserToken` entity and persists it reactively with Panache. The `expiresAt` field is now correctly calculated by adding `getAccessTokenExpiresIn()` (in seconds) to the current system time (in milliseconds).

```java
  private Uni<Response> handleTokens(Tokens tokens, String state) {
  var client = WebClient.create(vertx);

  return client.getAbs(USERINFO_ENDPOINT)
    .putHeader("Authorization", "Bearer " + tokens.getAccessToken()).send().flatMap(resp -> {
      if (resp.statusCode()!=Response.Status.OK.getStatusCode()) {
        return Uni.createFrom().item(Response.serverError().entity(
            new ServiceError(
              resp.statusCode(),
              "Userinfo failed with status: " + resp.statusCode()))
          .build());
      }
      JsonObject userInfo = resp.bodyAsJsonObject();

      var sub = userInfo.getString("sub");
      var email = userInfo.getString("email");

      var userToken = new UserToken();
      userToken.userSub = sub;
      userToken.email = email;
      userToken.accessToken = tokens.getAccessToken();
      userToken.refreshToken = tokens.getRefreshToken();
      userToken.expiresAt = tokens.getAccessTokenExpiresAt() * 1000;
      return Panache.withTransaction(() -> userToken.persist().replaceWith(userToken)).map(persisted -> Response.ok(new ConnectResponse(persisted.id, persisted.email)).build());
    })
    .onFailure().recoverWithItem(t -> Response.serverError().entity(
      new ServiceError(Response.Status.INTERNAL_SERVER_ERROR.getStatusCode(), "Error processing tokens: " + t.getMessage())).build())
    .onItemOrFailure().invoke(client::close);
}
```

**What's happening here:**

- We use Vertx's `WebClient` for the async HTTP call to userinfo—reactive all the way.
- Parse the JSON response for user details.
- Store in `UserToken`: Access token for API calls, refresh for renewals, expiry (converted to millis), and user identifiers.
- Wrap persistence in `Panache.withTransaction` to ensure atomicity.
- Clean up the client and handle failures gracefully.

The endpoint in `GoogleConnectResource.java` now delegates to the `GoogleTokenManager`:

```java

import jakarta.ws.rs.GET;
import jakarta.ws.rs.QueryParam;

@GET
@Path("callback")
public Uni<Response> callback(
  @QueryParam("code") String code, @QueryParam("state") String state) {
  return tokenManager.handleCallback(code, state);
}
```

Note: In prod, validate the `state` param against what you generated in `/connect` to block CSRF. We skipped it here for brevity, but add it!
This secures the tokens in Postgres. Next, we'll cover retrieving and refreshing them.

### Retrieving and Refreshing Tokens (/token/{id} Endpoint)

With tokens safely stored, the real value comes from retrieving them— and automatically refreshing if they're expired. This is handled in the `/token/{id}` endpoint, where `id` is the database ID of the `UserToken`. It's a smart setup: check expiry, serve the current access token if valid, or use the refresh token to get a new one via OIDC. Returns the UserToken as JSON with a possibly refreshed access token.

The core logic lives in `GoogleTokenManager.java`'s `getAccessToken` method. It fetches the entity by ID, checks if the access token is expired (with a 60-second buffer for clock skew), and refreshes if needed. Error responses now use the `ServiceError` record. If the token is not expired, its expiry date and time are logged.

Here's the method (abridged for focus):

```java
import com.acme.ServiceError;
import com.acme.UserToken;
import io.quarkus.hibernate.reactive.panache.Panache;
import io.quarkus.logging.Log;
import io.smallrye.mutiny.Uni;
import jakarta.ws.rs.core.Response;

public Uni<Response> getAccessToken(Long id) {
  return Panache.withTransaction(() -> UserToken.<UserToken>findById(id).onItem().transformToUni(userToken -> {
      if (userToken==null) {
        return Uni.createFrom().item(Response.status(Response.Status.NOT_FOUND).entity(new ServiceError(404, "UserToken not found")).build());
      }

      if (userToken.isAccessTokenExpired()) {
        if (userToken.refreshToken==null) {
          return Uni.createFrom().item(Response.status(Response.Status.UNAUTHORIZED).entity(new ServiceError(401, "Refresh token not available")).build());
        }

        var extraParams = new HashMap<String, String>();
        extraParams.put("refresh_token", userToken.refreshToken);
        extraParams.put("grant_type", "refresh_token");

        return oidcClient.getTokens(extraParams).onItem().transformToUni(
            refreshedTokens -> {
              userToken.accessToken = refreshedTokens.getAccessToken();
              userToken.expiresAt = refreshedTokens.getAccessTokenExpiresIn() * 1000;
              if (refreshedTokens.getRefreshToken()!=null) {
                userToken.refreshToken = refreshedTokens.getRefreshToken();
              }
              return userToken.persist().replaceWith(userToken);
            })
          .onItem().transform(updatedToken -> Response.ok(updatedToken.accessToken).build())
          .onFailure().recoverWithItem(t -> Response.serverError().entity(
            new ServiceError(500, "Failed to refresh token: " + t.getMessage())).build());
      } else {
        Log.infof("Token for user %s is not expired. Expiry date: %s", userToken.email, new Date(userToken.expiresAt));
        return Uni.createFrom().item(Response.ok(userToken.accessToken).build());
      }
    }))
    .onFailure().recoverWithItem(t ->
      Response.serverError().entity(new ServiceError(500, "Error accessing token: " + t.getMessage())).build());
}
```

**Key highlights:**

- `isAccessTokenExpired()` in `UserToken.java`: Compares current time to expiresAt minus a buffer. Simple but effective.
- For refresh: Use `OidcClient.getTokens()` with `grant_type=refresh_token`—Quarkus handles the endpoint and auth.
- Update the entity with new tokens and expiry, persist it, and return the fresh access token.
- Everything's wrapped in a transaction for consistency, and failures are caught with meaningful `ServiceError` responses.
- If the token is not expired, the expiry date and time are logged for debugging and monitoring.

The REST exposure in `GoogleConnectResource.java` now delegates to the `GoogleTokenManager`:

```java

import jakarta.ws.rs.GET;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.core.MediaType;

@GET
@Path("token/{id}")
@Produces(MediaType.TEXT_PLAIN)
public Uni<Response> getAccessToken(@PathParam("id") Long id) {
  return tokenManager.getAccessToken(id);
}
```

In practice, call `http://localhost:8080/token/1` (replace `{id}` with your stored ID), and it'll return the UserToken JSON.
This keeps your app authorized without manual intervention.

### Database Entity and Persistence

To store the tokens and user details, we use a simple JPA entity with Hibernate Reactive Panache. This makes database interactions reactive and easy—Panache handles CRUD ops out of the box, and since we're reactive, it plays nice with Mutiny's Uni for non-blocking persistence.

The UserToken.java class is our entity:

```java

import io.quarkus.hibernate.reactive.panache.PanacheEntity;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;

@Entity
public class UserToken extends PanacheEntity {

  public String userSub; // Google's unique subject ID from ID token
  public String email; // User's email from ID token

  @Column(name = "access_token", columnDefinition = "text")
  public String accessToken; // Access token for Google APIs

  @Column(name = "refresh_token", columnDefinition = "text")
  public String refreshToken; // Refresh token for renewing access

  public Long expiresAt;

  public Long getId() {
    return id;
  }

  public void setId(Long id) {
    this.id = id;
  }

  public boolean isAccessTokenExpired() {
    if (expiresAt==null) {
      return true;
    }
    // Adding a 60 second buffer for clock skew
    return System.currentTimeMillis() > (expiresAt - 60000);
  }
}
```

**Quick breakdown:**

- Extends `PanacheEntity` for auto-generated ID and basic methods like `persist()`, `findById()`.
- Fields: `userSub` and `email` from Google's userinfo; tokens and expiry for auth management.
- `isAccessTokenExpired()`: Checks against current time with a safety buffer to avoid edge cases from network delays or clock differences.
- Column definitions ensure tokens (which can be long strings) fit in the DB.
- The `expiresAt` field is stored as a `Long` representing milliseconds since the epoch, calculated by adding the `expires_in` value (from Google's token response, in seconds) to the current system time.

In the config (application.properties), we set `quarkus.hibernate-orm.schema-management.strategy=update`, so Quarkus auto-updates the schema on startup—no manual migrations needed for dev.

We use this entity in the callback (to persist new tokens) and token retrieval (to fetch and update). Everything's transactional via `Panache.withTransaction()`, keeping data consistent even in concurrent scenarios.

This setup is lightweight but scalable— for prod, consider adding indexes on userSub or encryption for tokens.

### Running and Testing the Service

With all the pieces in place, firing up the service is straightforward thanks to Quarkus's dev mode. Run `quarkus dev` in your project root—it compiles, starts the app on port 8080, spins up a Postgres container via Dev Services, and even gives you a live-reload UI for testing.

To test the flow:

1. Hit `http://localhost:8080/connect` in your browser. It will redirect you to the Google authorization page.
2. Log in with your Google account and consent. You'll redirect to `http://localhost:8080/callback?code=...&state=....`
3. If successful, you'll see the UserToken JSON.
4. Now test retrieval: `http://localhost:8080/token/{id}` (replace `{id}` with the one from step 3). It should return the UserToken JSON.
5. To test refresh: Manually tweak the `expiresAt` in the DB to a past timestamp, then hit the endpoint again. Watch the logs for refresh happening, and confirm the token updates.

For deeper testing, add unit tests with Quarkus's `@QuarkusTest` and RestAssured. Mock the OIDC client if needed to avoid real Google calls.

Common gotchas: Ensure your client ID/secret are set, and firewall allows port 8080. In prod, swap Dev Services for a real DB URL.

### Best Practices and Potential Enhancements

This setup works great for a proof-of-concept, but in real-world apps, especially with sensitive tokens, we need to layer on security and scalability. Let's cover some key best practices drawn from Quarkus docs and OAuth standards, plus ideas to level it up.

### Security First

- **Validate State in Callback:** Right now, we generate a `state` in `/connect` but don't check it in `handleCallback`. Store it temporarily (e.g., in a session, Redis, or even a short-lived DB entry) and verify it matches to thwart CSRF attacks. Google's docs emphasize this for OAuth flows.
- **Encrypt Tokens in Storage:** In UserToken, add a JPA converter (@Converter) on the token fields to encrypt/decrypt automatically, or use @PrePersist/@PreUpdate methods. Panache can rewrite field access to invoke getters/setters if defined, allowing encryption logic there.
- **HTTPS Everywhere:** Quarkus handles this via config (e.g., quarkus.tls.key-store.pem.0.cert=server.crt and quarkus.tls.key-store.pem.0.key=server.key for PEM format, plus quarkus.http.insecure-requests=disabled). See Quarkus TLS docs for details.
- **Emphasize not exposing refresh tokens in responses.**
- **Least Privilege Scopes:** Stick to `openid` `email` `profile` unless needed; avoid over-scoping. Never log tokens—use structured logging without sensitive data.
- **Token Revocation Handling:** Google can revoke refresh tokens (e.g., user changes password). In `getAccessToken`, if refresh fails with a revocation error (check response codes), delete the entity and force re-auth.
- **Rate Limiting and Input Validation:** Add Quarkus SmallRye Mutiny extensions or Vert.x guards to prevent abuse on endpoints.

### Transaction and Persistence Tips

From Hibernate Reactive Panache best practices:

- Always wrap ops in transactions (`Panache.withTransaction()`)—we do this, good! For high concurrency, it batches changes efficiently.
- For sensitive fields like tokens, use projections or DTOs when querying to avoid loading unnecessary data.
- In tests, use `@TestReactiveTransaction` to rollback changes automatically.

### Scalability and Performance

- **Caching Tokens:** Fetching/refreshing hits the DB and Google—cache valid access tokens (e.g., with Quarkus Caffeine or Redis extension) keyed by `userSub`, with TTL based on expiry minus buffer.
- **Paging for Multiple Users:** If scaling to many users, add repository methods with `PanacheQuery.page()` to list tokens without loading everything into memory.
- **Reactive All the Way:** We're using Mutiny `Uni`—keep composing for backpressure in larger apps.

### Enhancements to Explore

- **Integrate Google APIs:** Use the stored token to call services like Gmail or Drive. Inject another `WebClient` in `getAccessToken` to demo fetching emails post-refresh.
- **Multi-Tenant Support:** Index `userSub` in DB; add endpoints to list/connect by user.
- **UI Polish:** Wrap `/connect` in a redirect response for seamless browser flow, or build a frontend with Quarkus Qute templates.
- **Monitoring and Observability:** Add Quarkus Micrometer for metrics on refresh rates/failures; trace with OpenTelemetry.
- **Update Quarkus:** We're on 3.28.5 (latest stable as of October 2025)—check release notes for any OIDC client tweaks.
- **Testing Suite:** Expand with `@QuarkusTest`, mock OidcClient for unit tests, and integration tests simulating Google responses.

For prod, ditch Dev Services for a managed DB (e.g., AWS RDS), use Kubernetes for deployment, and secrets via env or config sources. This foundation scales well—adapt as needed!

### Final Thoughts

There you have it—a solid Quarkus service for handling Google OAuth tokens, from connection to storage and seamless refreshes. We've covered the essentials to get you integrating Google APIs without the usual headaches.

Key takeaways:

- Use Quarkus OIDC extensions for quick, secure auth flows.
- Leverage reactive tools like Mutiny and Panache for non-blocking DB ops.
- Always prioritize security: validate states, encrypt tokens, and handle revocations.
- Error handling is now more consistent with the `ServiceError` record.

Give this a spin in your own project—clone the code, tweak for your needs, and see how it performs. Got questions or improvements? Drop a comment below or share your fork. Next up, you could extend this to call specific Google APIs or deploy it on Kubernetes for real-world scale.

Have fun writing code!
