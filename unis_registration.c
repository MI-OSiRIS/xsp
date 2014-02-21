#define _GNU_SOURCE
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <math.h>
#include <err.h>
#include <jansson.h>
#include <pthread.h>

#include "curl_context.h"
#include "unis_registration.h"
#include "log.h"

static unis_config config;
static curl_context context;
static pthread_t thread;
static char *reg_str = NULL;
static char *service_instance = "\
{\
  \"status\": \"ON\",\
    \"$schema\": \"http://unis.incntre.iu.edu/schema/20120709/service#\",\
    \"serviceType\": \"\",\
    \"name\": \"\",\
    \"accessPoint\": \"\",\
    \"ttl\": 600\
}";

static int unis_make_reg_str(int interval, char *json, char **ret_json);
static void *unis_registration_thread(void *arg);

int unis_init(unis_config cc) {

  if (cc.name == NULL || !(config.name = strndup(cc.name, strlen(cc.name)))) {
    dbg_info("No UNIS registration name specified!");
    return -1;
  }

  if (cc.type == NULL || !(config.type = strndup(cc.type, strlen(cc.type)))) {
    dbg_info("No UNIS service type specified!");
    return -1;
  }

  if (cc.endpoint == NULL || !(config.endpoint = strndup(cc.endpoint, strlen(cc.endpoint)))) {
    dbg_info("No UNIS endpoint specified!");
    return -1;
  }

  if (cc.ifaces.count == 0) {
    dbg_info("No interfaces are specified");
    return -1;
  } else {
    config.ifaces.ip_ports = malloc(sizeof(unis_ip_port) * cc.ifaces.count);
    int i = 0;
    for (i = 0; i < cc.ifaces.count; ++i) {
      config.ifaces.ip_ports[i].ip = strdup(cc.ifaces.ip_ports[i].ip);
      config.ifaces.ip_ports[i].port = cc.ifaces.ip_ports[i].port;
    }
    config.ifaces.count = cc.ifaces.count;
  }

  config.do_register = cc.do_register;

  config.refresh_timer = cc.refresh_timer;
  if (config.refresh_timer == UNIS_REFRESH_TO || config.refresh_timer <= 0) {
    dbg_info("Refresh time not specified, using default %d", UNIS_REFRESH_TO);
    config.refresh_timer = UNIS_REFRESH_TO;
  }

  config.registration_interval = cc.registration_interval;
  if (config.registration_interval == UNIS_REG_INTERVAL || config.registration_interval <= 0) {
    dbg_info("Registration interval not specified, using default %d", UNIS_REG_INTERVAL);
    config.registration_interval = UNIS_REG_INTERVAL;
  }

  /* we could also start a thread that retrieves and caches everything from UNIS
     for now, every call to the UNIS module will do an active query against the service */
  context.url = config.endpoint;
  context.use_ssl = 0;
  context.curl_persist = 0;

  if (init_curl(&context, 0) != 0) {
    dbg_info("Could not start CURL context");
    return -1;
  }

  /* do registration at init time
   *      otherwise, we app must call xsp_unis_register() */
  if (config.do_register) {
    unis_make_reg_str(config.registration_interval, NULL, &reg_str);

    /* start the registration thread */
    pthread_attr_t attr;
    if(pthread_attr_init(&attr) != 0) {
      err(0, "can not pthread_attr_init");
    }
    if(pthread_attr_setdetachstate(&attr,PTHREAD_CREATE_DETACHED) != 0) {
      err(0, "pthread_attr_setdetachstate failed");
    }
    if (pthread_create(&thread, &attr, unis_registration_thread, &config) != 0) {
      err(0, "Could not start UNIS registration thread");
      return -1;
    }

  }

  return 0;
}


static int unis_make_reg_str(int interval, char *json, char **ret_json) {
  json_t *root;
  json_t *listeners;
  json_error_t json_err;
  char *ips;
  int i = 0, once = 1, port = 0;

  root = json_loads(service_instance, 0, &json_err);
  if (!root) {
    dbg_info("Could not decode XSP service string: %d: %s", json_err.line, json_err.text);
  }

  json_object_set(root, "name", json_string(config.name));
  json_object_set(root, "serviceType", json_string(config.type));
  json_object_set(root, "ttl", json_integer(config.registration_interval));

  /* TODO: need to read service listeners config to get proto and port info
     assume tcp listeners on port 5006 on all interfaces for now */
  listeners = json_array();
  for(i = 0; i < config.ifaces.count; ++i) {
    json_t *entry;
    char buf[255];

    ips = config.ifaces.ip_ports[i].ip;
    port = config.ifaces.ip_ports[i].port;
    if (strchr(ips, ':') != NULL) {
      continue;
    } 
    else if (!strcmp(ips, "127.0.0.1")) {
      continue;
    }
    else {
      if(once) {
        snprintf(buf, sizeof(buf), "xsp://%s:%d", ips, port);
        json_object_set(root, "accessPoint", json_string(buf));
        once = 0;
      }
      /* listen on all non-loopback IPs */
      snprintf(buf, sizeof(buf), "%s/%d", ips, port);
      entry = json_object();
      json_object_set(entry, "tcp", json_string(buf));
      json_array_append_new(listeners, entry);
    }
  }
  json_object_set(root, "listeners", listeners);

  if (json != NULL) {
    json_t *arg_root;
    arg_root = json_loads(json, 0, &json_err);
    if (!arg_root) {
      dbg_info("Could not decode JSON paramater: %d: %s", json_err.line, json_err.text);
    }
    else {
      /* TODO: merge passed-in JSON with defaults */
    }
  }

  //dbg_info("%s\n", json_dumps(root, JSON_INDENT(2)));
  *ret_json = json_dumps(root, JSON_COMPACT);

  return 0;
}

static void *unis_registration_thread(void *arg) {
  struct timeval now;
  unis_config *cfg = (unis_config *)arg;
  curl_response *response;
  json_t *reg_json;
  json_error_t json_err;
  char *url;
  char *send_str;
  char *sid = NULL;

  asprintf(&url, "%s/%s", cfg->endpoint, "services");

  while (1) {
    if (reg_str != NULL) {
      reg_json = json_loads(reg_str, 0, &json_err);
      if (!reg_json) {
        /* we should validate the reg_str against the XSP Service schema
http://unis.incntre.iu.edu/schema/ext/xspservice/1/xspservice */
        err(5, "Could not decode registration string: %d: %s",
            json_err.line, json_err.text);
        continue;
      }

      gettimeofday(&now, NULL);
      json_object_set(reg_json, "ts", json_integer(now.tv_sec*1e6 + now.tv_usec));
      if (sid) {
        dbg_info("\nsid=%s", sid);
        json_object_set(reg_json, "id", json_string(sid));
      }

      send_str = json_dumps(reg_json, JSON_COMPACT);

      /* with valid json, register to UNIS endpoint */
      curl_post_json_string(&context,
          url,
          send_str,
          &response);

      if (response && (response->status != 201)) {
        err(5, "Error registering to UNIS: %s", response->data);
      }
      /* first time we register, save ID for future updates */
      else if (response && response->data && !sid) {
        json_t *resp;
        json_t *key;
        resp = json_loads(response->data, 0, &json_err);
        if (!resp) {
          err(5, "Could not decode registration response! %d: %s",
              json_err.line, json_err.text);
          continue;
        }
        key = json_object_get(resp, "id");
        if (key) {
          sid = (char*)json_string_value(key);
        }
      }
      else if (response) {
        free_curl_response(response);
      }
    }
    sleep(cfg->registration_interval);
  }

  return NULL;
}

int unis_register_start(int interval, char *json) {
  return unis_make_reg_str(interval, json, &reg_str);
}

int unis_register_stop() {
  //TODO: do we require mutex to mutate reg_str??
  reg_str = NULL;
  return 0;
}

int unis_query(char *url, char *query, char **ret_str) {
  curl_response *response;
  char *qstr;
  int ret = 0;

  asprintf(&qstr, "%s/%s", url, query);
  dbg_info("\nQuery: %s\n", qstr);

  curl_get_json_string(&context,
      qstr,
      &response);

  if (response && (response->status != 200)) {
    dbg_info("Error querying UNIS: %lu: %s", response->status, response->data);
    ret = -1;
    *ret_str = NULL;
    goto exit;
  }

  if (ret_str && response && response->data) {
    *ret_str = malloc(strlen(response->data) * sizeof(char));
    strncpy(*ret_str, response->data, strlen(response->data));
  }

exit:
  free(qstr);
  if (response)
    free_curl_response(response);
  return ret;
}

int unis_get_service_access_points(char *sname, char ***ret_aps, int *num_aps) {
  json_t *json_ret;;
  json_error_t json_err;
  char *query;
  char *ret_str;
  char **aps;
  int num_objs;

  if (!ret_aps || !num_aps)
    return -1;

  asprintf(&query, "services?serviceType=%s", sname);

  unis_query(context.url, query, &ret_str);

  if (ret_str) {
    json_ret = json_loads(ret_str, 0, &json_err);
    if (!json_ret) {
      dbg_info("Could not decode response: %d: %s", json_err.line, json_err.text);
      return -1;
    }
  }

  num_objs = json_array_size(json_ret);
  if (num_objs == 0) {
    ret_aps = NULL;
    *num_aps = 0;
    return 0;
  }
  else {
    aps = (char**)malloc(num_objs*sizeof(char*));
    *num_aps = num_objs;
  }

  /* now we extract the fields we want

     this gets more complicated because updates to UNIS will generate similar
     entries with more recent timestamps.  we should get only the most recent
     entry for a particular UNIS object. more parsing... */

  int i;
  json_t *obj;
  json_t *key;

  //dbg_info("JSON_RESPONSE:\n%s\n", json_dumps(json_ret, JSON_INDENT(2)));

  for (i=0; i<num_objs; i++) {
    obj = json_array_get(json_ret, i);
    key = json_object_get(obj, "accessPoint");

    if (key)
      aps[i] = (char*)json_string_value(key);
  }


  *ret_aps = aps;

  free(query);

  return 0;
}
