package com.acme;

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
    if (expiresAt == null) {
      return true;
    }
    // Adding a 60 second buffer for clock skew
    return System.currentTimeMillis() > (expiresAt - 60000);
  }
}
