//go:build darwin && cgo

#import <Foundation/Foundation.h>
#import <ServiceManagement/ServiceManagement.h>
#import <stdlib.h>
#import <string.h>

#import "shim_darwin.h"

// copyError returns a malloc'd copy of err's localized description, or NULL.
static char *copyError(NSError *err) {
  if (err == nil) {
    return NULL;
  }
  const char *utf8 = [[err localizedDescription] UTF8String];
  if (utf8 == NULL) {
    return NULL;
  }
  return strdup(utf8);
}

int th_login_item_register(char **err_out) {
  if (@available(macOS 13.0, *)) {
    NSError *err = nil;
    BOOL ok = [[SMAppService mainAppService] registerAndReturnError:&err];
    if (!ok) {
      if (err_out != NULL) {
        *err_out = copyError(err);
      }
      return 1;
    }
    return 0;
  }
  if (err_out != NULL) {
    *err_out = strdup("Launch at Login requires macOS 13 or later");
  }
  return 1;
}

int th_login_item_unregister(char **err_out) {
  if (@available(macOS 13.0, *)) {
    NSError *err = nil;
    BOOL ok = [[SMAppService mainAppService] unregisterAndReturnError:&err];
    if (!ok) {
      if (err_out != NULL) {
        *err_out = copyError(err);
      }
      return 1;
    }
    return 0;
  }
  if (err_out != NULL) {
    *err_out = strdup("Launch at Login requires macOS 13 or later");
  }
  return 1;
}

int th_login_item_status(void) {
  if (@available(macOS 13.0, *)) {
    return (int)[[SMAppService mainAppService] status];
  }
  return -1;
}
