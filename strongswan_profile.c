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

#include "/home/ubuntu/src/strongswan/config.h"
#include <stdlib.h>
#include <string.h>
#include <credentials/containers/pkcs12.h>
#include <credentials/certificates/x509.h>
#include <credentials/sets/mem_cred.h>
#include <credentials/sets/callback_cred.h>
#include <library.h>
#include "strongswan_profile.h"

static void serializable_iface_init(JsonSerializableIface *iface) {}

G_DEFINE_TYPE_WITH_CODE(StrongSwanProfile, strongswan_profile, G_TYPE_OBJECT,
                        G_IMPLEMENT_INTERFACE(JSON_TYPE_SERIALIZABLE, serializable_iface_init))

char *chunk_to_str(chunk_t *chunk);

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
        case PROP_VPNNAME:
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
        case PROP_VPNNAME:
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
//    StrongSwanProfile *priv = strongswan_profile_get_instance_private(STRONGSWAN_PROFILE_SOURCE(gObject));
    G_OBJECT_CLASS(strongswan_profile_parent_class)->dispose(gObject);
}

static void strongswan_profile_finalize(GObject *gObject) {
    StrongSwanProfile *priv = strongswan_profile_get_instance_private(STRONGSWAN_PROFILE_SOURCE(gObject));
    if (priv->user_key) g_free(priv->user_key);
    if (priv->user_cert) g_free(priv->user_cert);
    if (priv->certificate) g_free(priv->certificate);
    if (priv->remote_addr) g_free(priv->remote_addr);
    if (priv->name) g_free(priv->name);
    if (priv->esp) g_free(priv->esp);
    if (priv->ike) g_free(priv->ike);
    if (priv->p12) g_free(priv->p12);
    if (priv->uuid) g_free(priv->uuid);
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
    properties[PROP_VPNNAME] = g_param_spec_string("name",
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
    StrongSwanProfile *profile;
    gsize length = 0;
    guchar *p12_data;
    chunk_t chunk;
    char *buf;
    JsonNode *root = json_parser_get_root(parser);

    if (root == NULL) { return NULL; }

    //TODO: check for memory leaks throughout all of this
    connection = nm_simple_connection_new();

    profile = (StrongSwanProfile *) json_gobject_deserialize(STRONGSWAN_PROFILE_TYPE_SOURCE, root);
    if (profile == NULL) { return NULL; }

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
            if (profile->p12) {
//                nm_setting_vpn_add_secret(s_vpn, "p12", profile->p12);
                p12_data = g_base64_decode(profile->p12, &length);
                g_assert(p12_data != NULL);
                chunk = chunk_create(p12_data, length);
                profile_t *pp = load_p12(chunk);
                chunk_free(&chunk);
                g_assert(pp != NULL);
                if (pp->ca->get_encoding(pp->ca, CERT_PEM, &chunk)) {
                    buf = chunk_to_str(&chunk);
                    nm_setting_vpn_add_secret(s_vpn, "certificate", buf);
                    free(buf);
                    chunk_free(&chunk);
                }
                if (pp->user_cert->get_encoding(pp->user_cert, CERT_PEM, &chunk)) {
                    buf = chunk_to_str(&chunk);
                    nm_setting_vpn_add_secret(s_vpn, "usercert", buf);
                    free(buf);
                    chunk_free(&chunk);
                }
                if (pp->private_key->get_encoding(pp->private_key, PRIVKEY_PEM, &chunk)) {
                    buf = chunk_to_str(&chunk);
                    nm_setting_vpn_add_secret(s_vpn, "userkey", buf);
                    free(buf);
                    chunk_free(&chunk);
                }
                pp->ca->destroy(pp->ca);
                pp->user_cert->destroy(pp->user_cert);
                pp->private_key->destroy(pp->private_key);
                free(pp);
            }
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

char *chunk_to_str(chunk_t *chunk) {
    char *buf = malloc((*chunk).len + 1);
    memset(buf, 0, (*chunk).len + 1);
    memcpy(buf, (*chunk).ptr, (*chunk).len);
    return buf;
}

NMConnection *strongswan_fuzz_import(const char *data, size_t size, GError **error) {
    NMConnection *connection;
    JsonParser *parser = json_parser_new();
    json_parser_load_from_data(parser, data, size, error);
    if (*error) {
        g_object_unref(parser);
        return NULL;
    }
    connection = parse_sswan(parser, error);
    g_object_unref(parser);
    return connection;
}


/**
 * Callback credential set pki uses
 */
static callback_cred_t *cb_set;

/**
 * Credential set to cache entered secrets
 */
static mem_cred_t *cb_creds;

static shared_key_type_t prompted;

static shared_key_t *cb(void *data, shared_key_type_t type,
                        identification_t *me, identification_t *other,
                        id_match_t *match_me, id_match_t *match_other) {
    char buf[64], *label, *secret = NULL;
    shared_key_t *shared;

    if (prompted == type) {
        return NULL;
    }
    switch (type) {
        case SHARED_PIN:
            label = "Smartcard PIN";
            break;
        case SHARED_PRIVATE_KEY_PASS:
            label = "Private key passphrase";
            break;
        default:
            return NULL;
    }
    snprintf(buf, sizeof(buf), "%s: ", label);
#ifdef HAVE_GETPASS
    secret = getpass(buf);
#endif
    if (secret && strlen(secret)) {
        prompted = type;
        if (match_me) {
            *match_me = ID_MATCH_PERFECT;
        }
        if (match_other) {
            *match_other = ID_MATCH_NONE;
        }
        shared = shared_key_create(type, chunk_clone(chunk_from_str(secret)));
        /* cache password in case it is required more than once */
        cb_creds->add_shared(cb_creds, shared, NULL);
        return shared->get_ref(shared);
    }
    return NULL;
}

/**
 * Register PIN/Passphrase callback function
 */
static void add_callback() {
    cb_set = callback_cred_create_shared(cb, NULL);
    lib->credmgr->add_set(lib->credmgr, &cb_set->set);
    cb_creds = mem_cred_create();
    lib->credmgr->add_set(lib->credmgr, &cb_creds->set);
}

/**
 * Unregister PIN/Passphrase callback function
 */
static void remove_callback() {
    lib->credmgr->remove_set(lib->credmgr, &cb_creds->set);
    cb_creds->destroy(cb_creds);
    lib->credmgr->remove_set(lib->credmgr, &cb_set->set);
    cb_set->destroy(cb_set);
}

static profile_t *load_p12(chunk_t data) {
    certificate_t *cert;
    private_key_t *key;
    chunk_t encoding;
    profile_t *profile = malloc(sizeof(profile_t));

    if (!library_init(NULL, "strongswan-import")) {
        library_deinit();
        exit(SS_RC_LIBSTRONGSWAN_INTEGRITY);
    }
    if (lib->integrity && lib->integrity->check_file(lib->integrity, "strongswan-import", "strongswan-import")) {
        exit(SS_RC_DAEMON_INTEGRITY);
    }
    //from config.h
    //"aes des rc2 sha2 sha1 md5 random x509 revocation pkcs1 pkcs7 pkcs8 pkcs12 dnskey sshkey pem openssl gmp ecdsa curve25519 hmac"
    // TODO: this uses additional config files, we could just inline this to avoid that.
    bool loaded = lib->plugins->load(lib->plugins,
                                     lib->settings->get_str(lib->settings, "strongswan-import.load", ""));
    g_assert(loaded == true);
    add_callback();

    pkcs12_t *p12 = lib->creds->create(lib->creds, CRED_CONTAINER, CONTAINER_PKCS12, BUILD_BLOB,
                                       data, BUILD_END);
    g_assert(p12 != NULL);
    enumerator_t *enumerator = p12->create_cert_enumerator(p12);
    while (enumerator->enumerate(enumerator, &cert)) {
        x509_t *x509 = (x509_t *) cert;
        // TODO: this should be X509_CA not X509_SELF_SIGNED but pyOpenSSL does not permit setting x509v3 flags
        if (x509->get_flags(x509) & X509_SELF_SIGNED)
            profile->ca = cert->get_ref(cert);
        else
            profile->user_cert = cert->get_ref(cert);
    }
    enumerator->destroy(enumerator);
    enumerator = p12->create_key_enumerator(p12);
    while (enumerator->enumerate(enumerator, &key))
        profile->private_key = key->get_ref(key);

    enumerator->destroy(enumerator);
    p12->container.destroy(&p12->container);
    remove_callback();
    return profile;
}

NMConnection *strongswan_import_sswan(NMVpnEditorPlugin *iface, const char *path, GError **error) {
    typedef struct profile_t profile_t;
    NMConnection *connection;
    JsonParser *parser = json_parser_new();
    json_parser_load_from_file(parser, path, error);
    if (*error) {
        g_object_unref(parser);
        return NULL;
    }
    connection = parse_sswan(parser, error);
    g_object_unref(parser);
    return connection;
}

static void strongswan_profile_init(StrongSwanProfile *self) {}

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
