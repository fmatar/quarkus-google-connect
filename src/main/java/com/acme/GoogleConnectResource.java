package com.acme;

import io.smallrye.mutiny.Uni;
import jakarta.inject.Inject;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import java.net.URI;

@Path("/")
public class GoogleConnectResource {

  @Inject GoogleTokenManager tokenManager;

  @GET
  @Path("connect")
  public Uni<Response> connect() {
    return tokenManager.connect().onItem().transform(uri -> Response.seeOther(URI.create(uri)).build());
  }

  @GET
  @Path("callback")
  @Produces(MediaType.APPLICATION_JSON)
  public Uni<Response> callback(@QueryParam("code") String code, @QueryParam("state") String state) {
    return tokenManager.handleCallback(code, state);
  }

  @GET
  @Path("token/{id}")
  @Produces(MediaType.APPLICATION_JSON)
  public Uni<Response> getAccessToken(@PathParam("id") Long id) {
    return tokenManager.getAccessToken(id);
  }
}
