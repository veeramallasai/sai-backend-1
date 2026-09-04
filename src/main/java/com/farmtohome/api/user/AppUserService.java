package com.farmtohome.api.user;

import com.farmtohome.api.common.ApiException;
import java.time.Instant;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AppUserService {
  private final AppUserRepository users;

  public AppUserService(AppUserRepository users) {
    this.users = users;
  }

  @Transactional
  AppUserDtos.Profile sync(String userId, AppUserDtos.SyncRequest request) {
    String uid = text(userId);
    if (uid.isEmpty()) {
      throw new ApiException(HttpStatus.UNAUTHORIZED, "Invalid login session.");
    }

    Instant now = Instant.now();
    boolean created = !users.existsById(uid);
    AppUserEntity user = users.findById(uid).orElseGet(AppUserEntity::new);
    if (created) {
      user.setFirebaseUid(uid);
      user.setCreatedAt(now);
      user.setActive(true);
    }

    String firstName = preferred(request == null ? null : request.firstName(), user.getFirstName());
    String lastName = preferred(request == null ? null : request.lastName(), user.getLastName());
    String displayName = (firstName + " " + lastName).trim();
    if (displayName.isEmpty()) displayName = preferred(user.getDisplayName(), uid);

    user.setFirstName(firstName.isEmpty() ? "User" : firstName);
    user.setLastName(lastName);
    user.setDisplayName(displayName.isEmpty() ? "User" : displayName);
    user.setEmail(preferred(user.getEmail(), uid + "@farmtohome.local"));
    String phone = preferred(request == null ? null : request.phoneNumber(), user.getPhoneNumber());
    user.setPhoneNumber(phone);
    String photo = preferred(request == null ? null : request.photoUrl(), user.getPhotoUrl());
    user.setPhotoUrl(photo);
    user.setShoppingMode(choice(request == null ? null : request.shoppingMode(), user.getShoppingMode(), "home", "shop"));
    user.setAccountType(choice(request == null ? null : request.accountType(), user.getAccountType(), "customer", "shop_owner"));
    user.setAuthProvider("local");
    user.setEmailVerified(true);
    user.setPhoneVerified(true);
    user.setActive(true);
    user.setLastLoginAt(now);
    user.setUpdatedAt(now);

    try {
      return AppUserDtos.Profile.from(users.saveAndFlush(user));
    } catch (DataIntegrityViolationException error) {
      throw new ApiException(
          HttpStatus.CONFLICT,
          "This email address or mobile number is already linked to another account.");
    }
  }

  @Transactional(readOnly = true)
  AppUserDtos.Profile get(String uid) {
    return users.findById(uid)
        .map(AppUserDtos.Profile::from)
        .orElseGet(() -> sync(uid, null));
  }

  private static String choice(Object requested, Object current, String first, String second) {
    String value = text(requested).toLowerCase();
    if (value.equals(first) || value.equals(second)) return value;
    value = text(current).toLowerCase();
    return value.equals(second) ? second : first;
  }

  private static String preferred(Object primary, Object fallback) {
    String value = text(primary);
    return value.isEmpty() ? text(fallback) : value;
  }

  private static String text(Object value) {
    return value == null ? "" : value.toString().trim();
  }
}
