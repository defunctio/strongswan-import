//
// Created by tim on 4/23/17.
//
#include <stdlib.h>
#include "strongswan_profile.h"

G_DEFINE_TYPE_WITH_CODE(StrongSwanProfile, strongswan_profile, G_TYPE_OBJECT,
                        G_IMPLEMENT_INTERFACE(JSON_TYPE_SERIALIZABLE, serializable_iface_init));

static GParamSpec *properties[N_PROPERTIES] = { NULL };

static void setting_vpn_add_data_item(NMSettingVpn *setting, const char *key, const char *value) {
    g_return_if_fail(NM_IS_SETTING_VPN(setting));
    g_return_if_fail(key && key[0]);
    g_return_if_fail(value && value[0]);
    //TODO: escape input (nmv_utils_str_utf8safe_escape_c)
    nm_setting_vpn_add_data_item(setting, key, value);
}

static void strongswan_profile_set_property(GObject *object, guint prop_id, const GValue *value, GParamSpec *pspec) {
    StrongSwanProfile *self = STRONGSWAN_PROFILE_SOURCE (object);

    switch (prop_id)
    {
        case PROP_UUID:
            g_free(self->uuid);
            self->uuid = g_value_dup_string(value);
            break;
        case PROP_NAME:
            g_free (self->name);
            self->name = g_value_dup_string(value);
            break;
        case PROP_TYPE:
            g_free(self->type);
            self->type = g_value_dup_string(value);
            break;
        case PROP_REMOTEADDR:
            g_free(self->remote_addr);
            self->remote_addr = g_value_dup_string(value);
            break;
        case PROP_LOCALP12:
            g_free(self->p12);
            self->p12 = g_value_dup_string(value);
            break;
        case PROP_MTU:
            self->mtu = g_value_get_double(value);
            break;
        default:
            G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
    }
}

static void strongswan_profile_get_property (GObject *object, guint prop_id, GValue *value, GParamSpec *pspec) {
    StrongSwanProfile *self = STRONGSWAN_PROFILE_SOURCE(object);
    switch (prop_id)
    {
        case PROP_UUID:
            g_value_set_string(value, self->uuid);
            break;
        case PROP_NAME:
            g_value_set_string(value, self->name);
            break;
        case PROP_TYPE:
            g_value_set_string(value, self->type);
            break;
        case PROP_REMOTEADDR:
            g_value_set_string(value, self->remote_addr);
            break;
        case PROP_LOCALP12:
            g_value_set_string(value, self->p12);
            break;
        case PROP_MTU:
            g_value_set_double(value, self->mtu);
            break;
        default:
            G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
    }
}

//ikev2-eap, ikev2-cert, ikev2-cert-eap, ikev2-eap-tls, ikev2-byod-eap
static void strongswan_profile_class_init (StrongSwanProfileClass *klass) {
    GObjectClass *objectClass= G_OBJECT_CLASS(klass);
    objectClass->get_property = strongswan_profile_get_property;
    objectClass->set_property = strongswan_profile_set_property;
    properties[PROP_UUID] = g_param_spec_string("uuid",
                                                "Connection UUID",
                                                "The UUID4 to be used in NetworkManager",
                                                NULL,
                                                G_PARAM_READWRITE);
    properties[PROP_NAME] = g_param_spec_string("name",
                                                "Profile name",
                                                "The name of the VPN Profile.",
                                                NULL,
                                                G_PARAM_READWRITE);
    //TODO: convert to enum
    properties[PROP_TYPE] = g_param_spec_string("type",
                                                "VPN connection type",
                                                "The type of VPN connection; one of (ikev2-eap, ikev2-cert, ikev2-cert-eap, ikev2-eap-tls, ikev2-byod-eap)",
                                                NULL,
                                                G_PARAM_READWRITE);
    properties[PROP_REMOTEADDR] = g_param_spec_string("remote.addr",
                                                      "Remote address",
                                                      "The remote address of the VPN Server",
                                                      NULL,
                                                      G_PARAM_READWRITE);
    properties[PROP_LOCALP12] = g_param_spec_string("local.p12",
                                                    "P12 CA/certificate/key",
                                                    "The PKCS12 container.",
                                                    NULL,
                                                    G_PARAM_READWRITE);
    properties[PROP_MTU] = g_param_spec_double("mtu",
                                               "MTU",
                                               "MTU to use for the VPN Profile.",
                                               1268,     // min (min allowed by ipv6)
                                               1500,  // max
                                               1386,  // default
                                               G_PARAM_READWRITE);

    g_object_class_install_properties (objectClass, N_PROPERTIES, properties);
}

NMConnection* strongswan_import_sswan(const char *path) {
    NMConnection *connection;
    NMSettingConnection *s_con;
    NMSettingIPConfig *s_ip4;
    NMSettingVpn *s_vpn;
    GError *error = NULL;
    JsonParser *parser = json_parser_new();
    json_parser_load_from_file(parser, path, &error);
    JsonNode *root = json_parser_get_root(parser);

    //TODO: check for memory leaks throughout all of this
    connection = nm_simple_connection_new();

    if(error) {
        g_print("%s", error->message);
        g_error_free(error);
        g_object_unref(parser);
        return NULL;
    }
    StrongSwanProfile *foo = (StrongSwanProfile*)json_gobject_deserialize(STRONGSWAN_PROFILE_TYPE_SOURCE, root);
    g_print("%s , %s\n", foo->name, foo->uuid);
//    guint count = N_PROPERTIES;
//    GParamSpec **props = g_object_class_list_properties(G_OBJECT_GET_CLASS(foo), &count);

    connection = nm_simple_connection_new();
    s_con = NM_SETTING_CONNECTION(nm_setting_connection_new());

//    if(foo->uuid == NULL)
//        foo->uuid = nm_utils_uuid_generate();

    g_object_set(G_OBJECT(s_con),
                 NM_SETTING_CONNECTION_UUID, foo->uuid,
                 NM_SETTING_CONNECTION_ID, foo->name,
                 NM_SETTING_CONNECTION_TYPE, NM_SETTING_VPN_SETTING_NAME,
                 NULL
    );
    nm_connection_add_setting(connection, NM_SETTING(s_con));

    s_ip4 = NM_SETTING_IP_CONFIG(nm_setting_ip4_config_new());
    nm_connection_add_setting(connection, NM_SETTING(s_ip4));
    g_object_set(s_ip4, NM_SETTING_IP_CONFIG_METHOD, NM_SETTING_IP4_CONFIG_METHOD_AUTO, NULL);


    s_vpn = NM_SETTING_VPN(nm_setting_vpn_new());
    //TODO: use network-manager-strongswan definition for name
    g_object_set(s_vpn, NM_SETTING_VPN_SERVICE_TYPE, "org.freedesktop.NetworkManager.strongswan", NULL);

//    setting_vpn_add_data_item(s_vpn, NM_SETTING_VPN_SERVICE_TYPE, foo->type);
    /*
     * vpn.data: ipcomp = no,
     * certificate = /home/tim/algo/configs/54.158.207.91/cacert.pem,
     * method = key,
     * virtual = yes,
     * address = 54.158.207.91,
     * encap = no,
     * usercert = /home/tim/algo/configs/54.158.207.91/pki/certs/dan.crt,
     * userkey = /home/tim/algo/configs/54.158.207.91/pki/private/dan.key
     */

    setting_vpn_add_data_item(s_vpn, "address", foo->remote_addr);
    setting_vpn_add_data_item(s_vpn, "method", "key");
    setting_vpn_add_data_item(s_vpn, "ipcomp", "no");
    setting_vpn_add_data_item(s_vpn, "virtual", "yes");

//    g_object_set(G_OBJECT(s_vpn),
//                 NM_SETTING_VPN_SERVICE_TYPE, foo->type,
//                 NULL
//    );
    nm_connection_add_setting(connection, NM_SETTING(s_vpn));

    g_object_unref(parser);
    return connection;
}

static void strongswan_profile_init(StrongSwanProfile *self) {}
static void serializable_iface_init(JsonSerializableIface *iface) { }
