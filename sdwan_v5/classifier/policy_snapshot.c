#include "classifier.h"

#include <json-c/json.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <sys/time.h>

static int class_index(const sdwan_policy *policy, const char *name) {
  for (uint16_t i = 0; i < policy->class_count; ++i)
    if (strcmp(policy->classes[i].name, name) == 0) return i;
  return -1;
}

static uint32_t path_mark(const sdwan_policy *policy, const char *name) {
  for (uint8_t i = 0; i < policy->path_count; ++i)
    if (strcmp(policy->paths[i].name, name) == 0) return policy->paths[i].mark;
  return 0;
}

bool sdwan_policy_store_init(sdwan_policy_store *store, const sdwan_config *config) {
  memset(store, 0, sizeof(*store));
  if (pthread_rwlock_init(&store->lock, NULL) != 0) return false;
  snprintf(store->expected_site, sizeof(store->expected_site), "%s", config->site);
  store->path_mask = config->path_mask;
  store->configured_fail_open = config->fail_open;
  store->active.version = 1; store->active.expires_ms = UINT64_MAX;
  store->active.path_count = 1; store->active.paths[0].mark = config->fallback_mark & config->path_mask;
  snprintf(store->active.paths[0].name, sizeof(store->active.paths[0].name), "fallback");
  store->active.class_count = 1; store->active.unknown_class = 0;
  snprintf(store->active.classes[0].name, sizeof(store->active.classes[0].name), "unknown");
  store->active.classes[0].path_count = 1;
  store->active.classes[0].ranked_marks[0] = store->active.paths[0].mark;
  store->active.fail_open = config->fail_open;
  return true;
}

void sdwan_policy_store_destroy(sdwan_policy_store *store) { pthread_rwlock_destroy(&store->lock); }

bool sdwan_policy_update_json(sdwan_policy_store *store, const char *text, size_t length) {
  struct json_tokener *tokener = json_tokener_new();
  struct json_object *root = json_tokener_parse_ex(tokener, text, (int)length);
  if (!root || json_tokener_get_error(tokener) != json_tokener_success) goto invalid;
  sdwan_policy next = {0};
  struct json_object *item, *paths, *classes, *apps, *categories;
  if (!json_object_object_get_ex(root, "schema_version", &item) || json_object_get_int(item) != 4) goto invalid;
  if (!json_object_object_get_ex(root, "site", &item)) goto invalid;
  snprintf(next.site, sizeof(next.site), "%s", json_object_get_string(item));
  if (strcmp(next.site, store->expected_site) != 0) goto invalid;
  if (!json_object_object_get_ex(root, "version", &item)) goto invalid;
  next.version = (uint64_t)json_object_get_int64(item);
  if (!json_object_object_get_ex(root, "epoch", &item)) goto invalid;
  next.epoch = (uint64_t)json_object_get_int64(item);
  if (!json_object_object_get_ex(root, "created_at", &item)) goto invalid;
  next.created_ms = (uint64_t)(json_object_get_double(item) * 1000.0);
  if (!json_object_object_get_ex(root, "expires_at", &item)) goto invalid;
  next.expires_ms = (uint64_t)(json_object_get_double(item) * 1000.0);
  if (!json_object_object_get_ex(root, "catalog_version", &item)) goto invalid;
  next.catalog_version = (uint64_t)json_object_get_int64(item);
  if (!json_object_object_get_ex(root, "generation", &item)) goto invalid;
  snprintf(next.generation, sizeof(next.generation), "%s", json_object_get_string(item));
  if (!next.version || !next.catalog_version || !next.generation[0] ||
      next.expires_ms <= next.created_ms) goto invalid;
  if (!json_object_object_get_ex(root, "fail_mode", &item)) goto invalid;
  const char *fail_mode = json_object_get_string(item);
  if (strcmp(fail_mode, "open") != 0 && strcmp(fail_mode, "closed") != 0) goto invalid;
  next.fail_open = strcmp(fail_mode, "open") == 0;
  if (next.fail_open != store->configured_fail_open) goto invalid;
  if (!json_object_object_get_ex(root, "path_marks", &paths) || !json_object_is_type(paths, json_type_object)) goto invalid;
  {
    json_object_object_foreach(paths, name, value) {
      if (next.path_count >= SDWAN_MAX_PATHS) goto invalid;
      snprintf(next.paths[next.path_count].name, sizeof(next.paths[next.path_count].name), "%s", name);
      uint32_t mark = (uint32_t)json_object_get_int64(value);
      if (!mark || (mark & ~store->path_mask)) goto invalid;
      for (uint8_t i = 0; i < next.path_count; ++i)
        if (next.paths[i].mark == mark) goto invalid;
      next.paths[next.path_count++].mark = mark;
    }
  }
  if (!next.path_count || !json_object_object_get_ex(root, "ranked_paths", &classes) ||
      !json_object_is_type(classes, json_type_object)) goto invalid;
  {
    json_object_object_foreach(classes, name, ranking) {
      if (next.class_count >= SDWAN_MAX_CLASSES || !json_object_is_type(ranking, json_type_array)) goto invalid;
      sdwan_class_policy *class_policy = &next.classes[next.class_count++];
      snprintf(class_policy->name, sizeof(class_policy->name), "%s", name);
      size_t count = json_object_array_length(ranking);
      if (count != next.path_count || count > SDWAN_MAX_PATHS) goto invalid;
      class_policy->path_count = (uint8_t)count;
      for (size_t i = 0; i < count; ++i) {
        uint32_t mark = path_mark(&next, json_object_get_string(json_object_array_get_idx(ranking, i)));
        if (!mark) goto invalid;
        for (size_t j = 0; j < i; ++j)
          if (class_policy->ranked_marks[j] == mark) goto invalid;
        class_policy->ranked_marks[i] = mark;
      }
    }
  }
  if (!next.class_count || !json_object_object_get_ex(root, "unknown_class", &item)) goto invalid;
  int unknown = class_index(&next, json_object_get_string(item)); if (unknown < 0) goto invalid;
  next.unknown_class = (uint16_t)unknown;
  if (!json_object_object_get_ex(root, "applications", &apps) ||
      !json_object_is_type(apps, json_type_object)) goto invalid;
  {
    json_object_object_foreach(apps, name, class_name) {
      if (next.app_count >= SDWAN_MAX_APPS) goto invalid;
      int index = class_index(&next, json_object_get_string(class_name)); if (index < 0) goto invalid;
      snprintf(next.applications[next.app_count].application,
               sizeof(next.applications[next.app_count].application), "%s", name);
      next.applications[next.app_count++].class_index = (uint16_t)index;
    }
  }
  if (!json_object_object_get_ex(root, "categories", &categories) ||
      !json_object_is_type(categories, json_type_object)) goto invalid;
  {
    json_object_object_foreach(categories, name, class_name) {
      if (next.category_count >= SDWAN_MAX_CATEGORIES) goto invalid;
      int index = class_index(&next, json_object_get_string(class_name)); if (index < 0) goto invalid;
      snprintf(next.categories[next.category_count].category,
               sizeof(next.categories[next.category_count].category), "%s", name);
      next.categories[next.category_count++].class_index = (uint16_t)index;
    }
  }
  if (next.expires_ms <= (uint64_t)time(NULL) * 1000u) goto invalid;
  pthread_rwlock_wrlock(&store->lock);
  bool stale = strcmp(next.generation, store->active.generation) == 0 && next.version <= store->active.version;
  if (!stale) store->active = next;
  pthread_rwlock_unlock(&store->lock);
  if (stale) atomic_fetch_add(&store->rejected_stale, 1); else atomic_fetch_add(&store->accepted, 1);
  json_object_put(root); json_tokener_free(tokener); return !stale;
invalid:
  atomic_fetch_add(&store->rejected_invalid, 1);
  if (root) json_object_put(root);
  json_tokener_free(tokener);
  return false;
}

uint32_t sdwan_policy_choose(sdwan_policy_store *store, const char *application,
                             const char *category, uint32_t fallback) {
  uint32_t result = fallback;
  pthread_rwlock_rdlock(&store->lock);
  uint64_t wall_ms = (uint64_t)time(NULL) * 1000u;
  if (wall_ms >= store->active.expires_ms) {
    pthread_rwlock_unlock(&store->lock);
    return fallback;
  }
  uint16_t index = store->active.unknown_class;
  for (uint16_t i = 0; i < store->active.app_count; ++i)
    if (strcasecmp(application, store->active.applications[i].application) == 0) {
      index = store->active.applications[i].class_index; break;
    }
  if (index == store->active.unknown_class) {
    for (uint16_t i = 0; i < store->active.category_count; ++i)
      if (strcasecmp(category, store->active.categories[i].category) == 0) {
        index = store->active.categories[i].class_index; break;
      }
  }
  if (index < store->active.class_count && store->active.classes[index].path_count)
    result = store->active.classes[index].ranked_marks[0];
  pthread_rwlock_unlock(&store->lock);
  return result;
}

void *sdwan_policy_listener(void *argument) {
  struct { sdwan_policy_store *store; sdwan_config *config; } *context = argument;
  int fd = socket(AF_UNIX, SOCK_DGRAM, 0); if (fd < 0) return NULL;
  struct sockaddr_un address = {.sun_family = AF_UNIX};
  snprintf(address.sun_path, sizeof(address.sun_path), "%s", context->config->policy_socket);
  unlink(address.sun_path);
  if (bind(fd, (struct sockaddr *)&address, sizeof(address)) != 0) { close(fd); return NULL; }
  struct timeval timeout = {.tv_sec = 1}; setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
  char buffer[65536];
  while (!sdwan_stop) {
    ssize_t count = recv(fd, buffer, sizeof(buffer), 0);
    if (count > 0) sdwan_policy_update_json(context->store, buffer, (size_t)count);
  }
  close(fd); unlink(address.sun_path); return NULL;
}
