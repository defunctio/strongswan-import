//
// Created by ubuntu on 6/5/17.
//

#ifndef STRONGSWAN_IMPORT_STRONGSWAN_HH_H
#define STRONGSWAN_IMPORT_STRONGSWAN_HH_H
#include <NetworkManager.h>

G_BEGIN_DECLS

NMConnection *strongswan_import_sswan(NMVpnEditorPlugin *iface, const char *path, GError **error);
NMConnection *strongswan_fuzz_import(const char *data, size_t size, GError **error);

G_END_DECLS

#endif //STRONGSWAN_IMPORT_STRONGSWAN_HH_H
