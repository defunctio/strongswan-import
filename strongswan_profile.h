/*
 *   MIT License
 *
 *   Copyright (c) 2017 defunct (https://keybase.io/defunct)
 *
 *   Permission is hereby granted, free of charge, to any person obtaining a copy
 *   of this software and associated documentation files (the "Software"), to deal
 *   in the Software without restriction, including without limitation the rights
 *   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *   copies of the Software, and to permit persons to whom the Software is
 *   furnished to do so, subject to the following conditions:
 *
 *   The above copyright notice and this permission notice shall be included in all
 *   copies or substantial portions of the Software.
 *
 *   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 *   SOFTWARE.
 */

#ifndef STRONGSWAN_PROFILE_H
#define STRONGSWAN_PROFILE_H 1

#include <glib-object.h>
#include <json-glib/json-glib.h>
#include <NetworkManager.h>

G_BEGIN_DECLS

#define STRONGSWAN_VPN_METHOD_TYPE (strongswan_vpn_method_get_type())
#define STRONGSWAN_PROFILE_TYPE_SOURCE (strongswan_profile_get_type())
#define STRONGSWAN_PROFILE_SOURCE(obj)             (G_TYPE_CHECK_INSTANCE_CAST ((obj), STRONGSWAN_PROFILE_TYPE_SOURCE, StrongSwanProfile))
#define STRONGSWAN_PROFILE_SOURCE_CLASS(klass)     (G_TYPE_CHECK_CLASS_CAST ((klass), STRONGSWAN_PROFILE_TYPE_SOURCE, StrongSwanProfileClass))
#define STRONGSWAN_PROFILE_IS_SOURCE(obj)          (G_TYPE_CHECK_INSTANCE_TYPE ((obj), STRONGSWAN_PROFILE_TYPE_SOURCE))
#define STRONGSWAN_PROFILE_IS_SOURCE_CLASS(klass)  (G_TYPE_CHECK_CLASS_TYPE ((klass), STRONGSWAN_PROFILE_TYPE_SOURCE))
#define STRONGSWAN_PROFILE_SOURCE_GET_CLASS(obj)   (G_TYPE_INSTANCE_GET_CLASS ((obj), STRONGSWAN_PROFILE_TYPE_SOURCE, StrongSwanProfileClass))
enum {
    PROP_ZERO,
    PROP_UUID,
    PROP_VPNNAME,
    PROP_METHOD,
    PROP_REMOTEADDR,
    PROP_LOCALP12,
    PROP_IKE,
    PROP_ESP,
    PROP_CERT,
    PROP_USERCERT,
    PROP_USERKEY,
    N_PROPERTIES
};

typedef enum { /*< prefix=METHOD >*/
    METHOD_NONE,
    METHOD_KEY,
    METHOD_AGENT,
    METHOD_SMARTCARD,
    METHOD_EAP
} VPNMethod;

typedef struct StrongSwanProfile_ {
    GObject parent;
    gchar *uuid;
    gchar *name;
    VPNMethod method;
    gchar *remote_addr;
    gchar *p12;
    gchar *ike;
    gchar *esp;
    gchar *certificate;
    gchar *user_cert;
    gchar *user_key;
} StrongSwanProfile;

typedef struct StrongSwanProfileClass_ {
    GObjectClass parent_class;
} StrongSwanProfileClass;

GType strongswan_profile_get_type(void);
GType strongswan_vpn_method_get_type(void);
NMConnection *parse_sswan(JsonParser *parser, GError **error);
NMConnection *strongswan_import_sswan(NMVpnEditorPlugin *iface, const char *path, GError **error);
NMConnection *strongswan_fuzz_import(const char *data, size_t size, GError **error);

G_END_DECLS

#endif /* STRONGSWAN_PROFILE_H */