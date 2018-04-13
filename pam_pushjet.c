/* pam_pushjet module */

/*
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <curl/curl.h>
#include <libconfig.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#define PAM_SM_AUTH
#define PAM_SM_PASSWORD

#include <security/pam_ext.h>
#include <security/pam_modules.h>

#define OBTAIN(item, value, default_value)                                     \
  do {                                                                         \
    (void)pam_get_item(pamh, item, &value);                                    \
    value = value ? value : default_value;                                     \
  } while (0)

static void log_items(pam_handle_t *pamh, const char *function, int flags) {

  /* PAM variables */
  const void *service, *user, *terminal, *rhost, *ruser;

  OBTAIN(PAM_SERVICE, service, "<unknown>");
  OBTAIN(PAM_TTY, terminal, "<unknown>");
  OBTAIN(PAM_USER, user, "<unknown>");
  OBTAIN(PAM_RUSER, ruser, "<unknown>");
  OBTAIN(PAM_RHOST, rhost, "<unknown>");

  const char *pushjet_secret;
  const char *pushjet_api;

  /* libconfig to get pushjet secret */
  config_t cfg;
  config_init(&cfg);
  if (config_read_file(&cfg, "/etc/pam_pushjet") != CONFIG_TRUE) {
    /* TODO: warn somehow there is no secret? */
    fprintf(stderr, "pam_pushjet: could not read /etc/pam_pushjet\n");
    return;
  }
  if (config_lookup_string(&cfg, "secret", &pushjet_secret) != CONFIG_TRUE) {
    /* TODO: warn somehow there is no secret? */
    fprintf(stderr, "pam_pushjet: could not read secret\n");
    return;
  }
  if (config_lookup_string(&cfg, "api", &pushjet_api) != CONFIG_TRUE) {
    /* TODO: warn somehow there is no secret? */
    fprintf(stderr, "pam_pushjet: could not read api address!\n");
    pushjet_api = strdup("https://api.pushjet.io/message");
    return;
  }

  /* TODO: this can be much nicer */
  char *message = malloc(sizeof(char) * (64 + strlen(user) + strlen(terminal)));
  char *post_param =
      malloc(sizeof(char) * (128 + strlen(pushjet_secret) + strlen(message)));
  sprintf(message, "User %s logging in at terminal %s", user, terminal);
  sprintf(post_param, "secret=%s&message=%s&level=3&title=PAM Notification",
          pushjet_secret, message);

  CURL *curl;
  CURLcode res;

  curl_global_init(CURL_GLOBAL_ALL);
  curl = curl_easy_init();

  /* get a curl handle */
  curl = curl_easy_init();
  if (curl) {
    curl_easy_setopt(curl, CURLOPT_URL, pushjet_api);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_param);

    res = curl_easy_perform(curl);
    if (res != CURLE_OK)
      fprintf(stderr, "curl_easy_perform() failed: %s\n",
              curl_easy_strerror(res));

    curl_easy_cleanup(curl);
  }
  curl_global_cleanup();
  config_destroy(&cfg);
  free(message);
  free(post_param);
}

/* --- authentication management functions (only) --- */

int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
                        const char **argv) {
  log_items(pamh, __FUNCTION__, flags);
  return PAM_IGNORE;
}

int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  log_items(pamh, __FUNCTION__, flags);
  return PAM_IGNORE;
}

/* password updating functions */

int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc,
                     const char **argv) {
  log_items(pamh, __FUNCTION__, flags);
  return PAM_IGNORE;
}

int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc,
                     const char **argv) {
  log_items(pamh, __FUNCTION__, flags);
  return PAM_IGNORE;
}

int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc,
                        const char **argv) {
  log_items(pamh, __FUNCTION__, flags);
  return PAM_IGNORE;
}

int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc,
                         const char **argv) {
  log_items(pamh, __FUNCTION__, flags);
  return PAM_IGNORE;
}

/* end of module definition */
