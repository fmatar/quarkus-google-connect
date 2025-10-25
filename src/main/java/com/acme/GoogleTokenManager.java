package com.acme;

import io.quarkus.hibernate.reactive.panache.Panache;
import io.quarkus.logging.Log;
import io.quarkus.oidc.client.OidcClient;
import io.quarkus.oidc.client.Tokens;
import io.smallrye.mutiny.Uni;
import io.vertx.core.json.JsonObject;
import io.vertx.mutiny.core.Vertx;
import io.vertx.mutiny.ext.web.client.WebClient;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;
import org.eclipse.microprofile.config.inject.ConfigProperty;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@ApplicationScoped
public class GoogleTokenManager {

  private static final String AUTHORIZATION_ENDPOINT =
    "https://accounts.google.com/o/oauth2/v2/auth";
  private static final String USERINFO_ENDPOINT =
    "https://openidconnect.googleapis.com/v1/userinfo";
  private final Map<String, String> stateMap = new ConcurrentHashMap<>();
  @Inject
  OidcClient oidcClient;
  @Inject
  Vertx vertx;
  @ConfigProperty(name = "quarkus.oidc-client.client-id")
  String clientId;
  @ConfigProperty(name = "app.google.redirect-uri", defaultValue = "http://localhost:8080/callback")
  String redirectUri;

  public Uni<String> connect() {
    return Uni.createFrom().item(() -> {
      var state = UUID.randomUUID().toString();
      stateMap.put(state, state);
      var authUrl = UriBuilder.fromUri(AUTHORIZATION_ENDPOINT)
        .queryParam("client_id", clientId)
        .queryParam("redirect_uri", redirectUri)
        .queryParam("scope", "openid email profile")
        .queryParam("response_type", "code")
        .queryParam("access_type", "offline")
        .queryParam("prompt", "consent")
        .queryParam("state", state);
      return authUrl.build().toString();
    });
  }

  public Uni<Response> handleCallback(String code, String state) {
    if (state==null || stateMap.remove(state)==null) {
      return Uni.createFrom().item(
        Response.status(Response.Status.BAD_REQUEST)
          .entity(new ServiceError(Response.Status.BAD_REQUEST.getStatusCode(), "Invalid state"))
          .build());
    }
    if (code==null) {
      return Uni.createFrom().item(
        Response.status(Response.Status.BAD_REQUEST)
          .entity(
            new ServiceError(Response.Status.BAD_REQUEST.getStatusCode(), "Missing code"))
          .build());
    }

    var extraParams = new HashMap<String, String>();
    extraParams.put("code", code);
    extraParams.put("redirect_uri", redirectUri);

    return oidcClient.getTokens(extraParams).flatMap(tokens -> handleTokens(tokens, state))
      .onFailure().recoverWithItem(t -> Response.serverError().entity(
        new ServiceError(Response.Status.INTERNAL_SERVER_ERROR.getStatusCode(), "Token exchange failed")).build());
  }

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

    public Uni<Response> getAccessToken(Long id) {
      return Panache.withTransaction(
          () ->
            UserToken.<UserToken>findById(id).onItem().transformToUni(
              userToken -> {
                if (userToken==null) {
                  return Uni.createFrom().item(Response.status(Response.Status.NOT_FOUND).entity(
                    new ServiceError(Response.Status.NOT_FOUND.getStatusCode(), "UserToken not found")).build());
                }

                if (userToken.isAccessTokenExpired()) {
                  if (userToken.refreshToken==null) {
                    return Uni.createFrom().item(Response.status(Response.Status.UNAUTHORIZED).entity(
                      new ServiceError(Response.Status.UNAUTHORIZED.getStatusCode(), "Refresh token not available")).build());
                  }

                  var extraParams = new HashMap<String, String>();
                  extraParams.put("refresh_token", userToken.refreshToken);
                  extraParams.put("grant_type", "refresh_token");

                  return oidcClient.getTokens(extraParams).onItem().transformToUni(refreshedTokens -> {
                      userToken.accessToken = refreshedTokens.getAccessToken();
                      userToken.expiresAt = refreshedTokens.getAccessTokenExpiresAt() * 1000;
                      if (refreshedTokens.getRefreshToken()!=null) {
                        userToken.refreshToken = refreshedTokens.getRefreshToken();
                      }
                      return userToken.persist().replaceWith(userToken);
                    })
                    .onItem().transform(updatedToken -> Response.ok(new AccessTokenResponse(updatedToken.accessToken)).build())
                    .onFailure().recoverWithItem(t -> Response.serverError().entity(new ServiceError(
                      Response.Status.INTERNAL_SERVER_ERROR.getStatusCode(), "Failed to refresh token: " + t.getMessage())).build());
                } else {
                  Log.infof("Token for user %s is not expired. Expiry date: %s", userToken.email, new Date(userToken.expiresAt));
                  return Uni.createFrom().item(Response.ok(new AccessTokenResponse(userToken.accessToken)).build());
                }
              }))
        .onFailure().recoverWithItem(t -> Response.serverError().entity(
          new ServiceError(Response.Status.INTERNAL_SERVER_ERROR.getStatusCode(), "Error accessing token: " + t.getMessage())).build());
    }

  public record ConnectResponse(Long id, String email) {
  }

  public record AccessTokenResponse(String accessToken) {
  }
}
