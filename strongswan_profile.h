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
    PROP_0,
    PROP_UUID,
    PROP_NAME,
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
static void serializable_iface_init(JsonSerializableIface *iface);
static void setting_vpn_add_data_item(NMSettingVpn *setting, const char *key, const char *value);
NMConnection *strongswan_import_sswan(const char *path);


G_END_DECLS

#endif /* STRONGSWAN_PROFILE_H */