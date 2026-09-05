#ifndef TREEHOUSE_LOGINITEM_SHIM_H
#define TREEHOUSE_LOGINITEM_SHIM_H

// Status codes mirror Apple's SMAppServiceStatus.
enum {
  TH_LOGIN_ITEM_NOT_REGISTERED = 0,
  TH_LOGIN_ITEM_ENABLED = 1,
  TH_LOGIN_ITEM_REQUIRES_APPROVAL = 2,
  TH_LOGIN_ITEM_NOT_FOUND = 3,
};

// th_login_item_register / th_login_item_unregister return 0 on success and a
// non-zero code on failure. On failure, when err_out is non-NULL it receives a
// malloc'd, NUL-terminated UTF-8 string the caller must free().
int th_login_item_register(char **err_out);
int th_login_item_unregister(char **err_out);

// Returns one of the TH_LOGIN_ITEM_* codes, or -1 when the running OS predates
// SMAppService (should not happen: the app requires macOS 13).
int th_login_item_status(void);

#endif
