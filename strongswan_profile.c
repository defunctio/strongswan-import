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

#include <stdlib.h>
#include <string.h>
#include "strongswan_profile.h"

G_DEFINE_TYPE_WITH_CODE(StrongSwanProfile, strongswan_profile, G_TYPE_OBJECT,
                        G_IMPLEMENT_INTERFACE(JSON_TYPE_SERIALIZABLE, serializable_iface_init));

static GParamSpec *properties[N_PROPERTIES] = {NULL};

static void setting_vpn_add_data_item(NMSettingVpn *setting, const char *key, const char *value) {
    g_return_if_fail(NM_IS_SETTING_VPN(setting));
    g_return_if_fail(key && key[0]);
    g_return_if_fail(value && value[0]);
    //TODO: escape input (nmv_utils_str_utf8safe_escape_c)
    nm_setting_vpn_add_data_item(setting, key, value);
}

static void strongswan_profile_set_property(GObject *object, guint prop_id, const GValue *value, GParamSpec *pspec) {
    StrongSwanProfile *self = STRONGSWAN_PROFILE_SOURCE (object);

    switch (prop_id) {
        case PROP_UUID:
            g_free(self->uuid);
            self->uuid = g_value_dup_string(value);
            break;
        case PROP_NAME:
            g_free(self->name);
            self->name = g_value_dup_string(value);
            break;
        case PROP_METHOD:
            self->method = (VPNMethod) g_value_get_enum(value);
            break;
        case PROP_REMOTEADDR:
            g_free(self->remote_addr);
            self->remote_addr = g_value_dup_string(value);
            break;
        case PROP_LOCALP12:
            g_free(self->p12);
            self->p12 = g_value_dup_string(value);
            break;
        case PROP_IKE:
            g_free(self->ike);
            self->ike = g_value_dup_string(value);
            break;
        case PROP_ESP:
            g_free(self->esp);
            self->esp = g_value_dup_string(value);
            break;
        case PROP_CERT:
            g_free(self->certificate);
            self->certificate = g_value_dup_string(value);
            break;
        case PROP_USERCERT:
            g_free(self->user_cert);
            self->user_cert = g_value_dup_string(value);
            break;
        case PROP_USERKEY:
            g_free(self->user_key);
            self->user_key = g_value_dup_string(value);
            break;
        default:
            G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
    }
}

static void strongswan_profile_get_property(GObject *object, guint prop_id, GValue *value, GParamSpec *pspec) {
    StrongSwanProfile *self = STRONGSWAN_PROFILE_SOURCE(object);
    switch (prop_id) {
        case PROP_UUID:
            g_value_set_string(value, self->uuid);
            break;
        case PROP_NAME:
            g_value_set_string(value, self->name);
            break;
        case PROP_METHOD:
            g_value_set_enum(value, self->method);
            break;
        case PROP_REMOTEADDR:
            g_value_set_string(value, self->remote_addr);
            break;
        case PROP_LOCALP12:
            g_value_set_string(value, self->p12);
            break;
        case PROP_IKE:
            g_value_set_string(value, self->ike);
            break;
        case PROP_ESP:
            g_value_set_string(value, self->esp);
            break;
        case PROP_CERT:
            g_value_set_string(value, self->certificate);
            break;
        case PROP_USERCERT:
            g_value_set_string(value, self->user_cert);
            break;
        case PROP_USERKEY:
            g_value_set_string(value, self->user_key);
            break;
        default:
            G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
    }
}


static void strongswan_profile_dispose(GObject *gObject) {
    StrongSwanProfile *priv = strongswan_profile_get_instance_private(STRONGSWAN_PROFILE_SOURCE(gObject));
    G_OBJECT_CLASS(strongswan_profile_parent_class)->dispose(gObject);
}

static void strongswan_profile_finalize(GObject *gObject) {
    StrongSwanProfile *priv = strongswan_profile_get_instance_private(STRONGSWAN_PROFILE_SOURCE(gObject));
    if(priv->user_key) g_free(priv->user_key);
    if(priv->user_cert) g_free(priv->user_cert);
    if(priv->certificate) g_free(priv->certificate);
    if(priv->remote_addr) g_free(priv->remote_addr);
    if(priv->name) g_free(priv->name);
    if(priv->esp) g_free(priv->esp);
    if(priv->ike) g_free(priv->ike);
    if(priv->p12) g_free(priv->p12);
    if(priv->uuid) g_free(priv->uuid);
}

static void strongswan_profile_class_init(StrongSwanProfileClass *klass) {
    GObjectClass *objectClass = G_OBJECT_CLASS(klass);
    objectClass->get_property = strongswan_profile_get_property;
    objectClass->set_property = strongswan_profile_set_property;
    objectClass->finalize = strongswan_profile_finalize;
    objectClass->dispose = strongswan_profile_dispose;
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
    properties[PROP_METHOD] = g_param_spec_enum("method",
                                                "VPN connection method",
                                                "The method of VPN connection; one of (key, agent, smartcard, eap)",
                                                STRONGSWAN_VPN_METHOD_TYPE,
                                                METHOD_NONE,
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
    properties[PROP_IKE] = g_param_spec_string("ike",
                                               "IKE Proposal",
                                               "Restrict the IKE proposal to this.",
                                               NULL,
                                               G_PARAM_READWRITE);
    properties[PROP_ESP] = g_param_spec_string("esp",
                                               "ESP Proposal",
                                               "Restrict the ESP proposal to this.",
                                               NULL,
                                               G_PARAM_READWRITE);
    properties[PROP_CERT] = g_param_spec_string("cert",
                                                "Certificate",
                                                "Server certificate",
                                                NULL,
                                                G_PARAM_READWRITE);
    properties[PROP_USERCERT] = g_param_spec_string("usercert",
                                                    "User certificate",
                                                    "User certificate",
                                                    NULL,
                                                    G_PARAM_READWRITE);
    properties[PROP_USERKEY] = g_param_spec_string("userkey",
                                                   "User key",
                                                   "User key",
                                                   NULL,
                                                   G_PARAM_READWRITE);

    g_object_class_install_properties(objectClass, N_PROPERTIES, properties);
}


NMConnection *parse_sswan(JsonParser *parser, GError **error) {
    NMConnection *connection;
    NMSettingConnection *s_con;
    NMSettingIPConfig *s_ip4;
    NMSettingVpn *s_vpn;
    JsonNode *root = json_parser_get_root(parser);

    if(root==NULL) { return NULL; }

    //TODO: check for memory leaks throughout all of this
    connection = nm_simple_connection_new();

    StrongSwanProfile *profile = (StrongSwanProfile *) json_gobject_deserialize(STRONGSWAN_PROFILE_TYPE_SOURCE, root);
    if(profile == NULL) { return NULL; }

    s_con = NM_SETTING_CONNECTION(nm_setting_connection_new());

    if (!profile->uuid)
        profile->uuid = nm_utils_uuid_generate();

    if (!profile->name) {
        //TODO: use STRONGSWAN error defines
#if !__has_feature(address_sanitizer)
        g_set_error(error, 2, 0, "Missing required field `name`");
#endif
        g_object_unref(parser);
        g_object_unref(profile);
        return NULL;
    }

    g_object_set(G_OBJECT(s_con),
                 NM_SETTING_CONNECTION_UUID, profile->uuid,
                 NM_SETTING_CONNECTION_ID, profile->name,
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

    if (profile->ike || profile->esp)
        setting_vpn_add_data_item(s_vpn, "proposal", "yes");
    if (profile->ike)
        setting_vpn_add_data_item(s_vpn, "ike", profile->ike);
    if (profile->esp)
        setting_vpn_add_data_item(s_vpn, "esp", profile->esp);

    if (!profile->remote_addr) {
        //TODO: use STRONGSWAN error defines
#if !__has_feature(address_sanitizer)
        g_set_error(error, 2, 0, "Missing required field `remote.addr`");
#endif
        g_object_unref(profile);
        g_object_unref(parser);
        return NULL;
    }
    setting_vpn_add_data_item(s_vpn, "address", profile->remote_addr);

    switch (profile->method) {
        case METHOD_KEY:
            setting_vpn_add_data_item(s_vpn, "method", "key");
            if (profile->certificate)
                setting_vpn_add_data_item(s_vpn, "certificate", profile->certificate);
            if (profile->user_cert)
                setting_vpn_add_data_item(s_vpn, "usercert", profile->user_cert);
            if (profile->user_key)
                setting_vpn_add_data_item(s_vpn, "userkey", profile->user_key);
            break;
        case METHOD_AGENT:
        case METHOD_SMARTCARD:
        case METHOD_EAP:
            //TODO: use STRONGSWAN error defines
#if !__has_feature(address_sanitizer)
            g_set_error(error, 2, 0, "Method currently not implemented.");
#endif
            g_object_unref(profile);
            g_object_unref(parser);
            g_object_unref(s_con);
            g_object_unref(s_vpn);
            return NULL;
        case METHOD_NONE:
        default:
            //TODO: use STRONGSWAN error defines
#if !__has_feature(address_sanitizer)
            g_set_error(error, 2, 0, "No VPN `method` was defined. `method` = (key, agent, smartcard, eap)");
#endif
            g_object_unref(profile);
            g_object_unref(parser);
            return NULL;
    }

    //TODO: make these values configurable
    setting_vpn_add_data_item(s_vpn, "ipcomp", "no");
    setting_vpn_add_data_item(s_vpn, "encap", "no");
    setting_vpn_add_data_item(s_vpn, "virtual", "yes");

    nm_connection_add_setting(connection, NM_SETTING(s_vpn));

    g_object_unref(profile);
    g_object_unref(parser);
    return connection;
}

NMConnection *strongswan_fuzz_import(const char *data, size_t size, GError **error) {
    JsonParser *parser = json_parser_new();
    json_parser_load_from_data(parser, data, size, error);
    if (*error) {
        g_object_unref(parser);
        return NULL;
    }
    NMConnection *connection =  parse_sswan(parser, error);
    g_object_unref(parser);
    return connection;
}

NMConnection *strongswan_import_sswan(const char *path, GError **error) {
    JsonParser *parser = json_parser_new();
    json_parser_load_from_file(parser, path, error);
    if (*error) {
        g_object_unref(parser);
        return NULL;
    }
    NMConnection *connection =  parse_sswan(parser, error);
    g_object_unref(parser);
    return connection;
}

static void strongswan_profile_init(StrongSwanProfile *self) {}

static void serializable_iface_init(JsonSerializableIface *iface) {}

GType strongswan_vpn_method_get_type() {
    static const GEnumValue values[] = {
            {METHOD_NONE,      "METHOD_NONE",      "none"},
            {METHOD_KEY,       "METHOD_KEY",       "key"},
            {METHOD_AGENT,     "METHOD_AGENT",     "agent"},
            {METHOD_SMARTCARD, "METHOD_SMARTCARD", "smartcard"},
            {METHOD_EAP,       "METHOD_EAP",       "eap"},
            {0, NULL, NULL}
    };
    return g_enum_register_static(g_intern_static_string("VPNMethod"), values);
}
