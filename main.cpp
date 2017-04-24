#include <iostream>
#include <glib.h>
#include <NetworkManager.h>
#include "strongswan_profile.h"

//extern "C" NMConnection* strongswan_import_sswan(const char *path);


static void
added_cb (GObject *client,
          GAsyncResult *result,
          gpointer user_data)
{
    GMainLoop *loop = (GMainLoop*)user_data;
    NMRemoteConnection *remote;
    GError *error = NULL;

    /* NM responded to our request; either handle the resulting error or
     * print out the object path of the connection we just added.
     */
    remote = nm_client_add_connection_finish (NM_CLIENT (client), result, &error);

    if (error) {
        g_print ("Error adding connection: %s", error->message);
        g_error_free (error);
    } else {
        g_print ("Added: %s\n", nm_connection_get_path (NM_CONNECTION (remote)));
        g_object_unref (remote);
    }

    /* Tell the mainloop we're done and we can quit now */
    g_main_loop_quit (loop);
}


int main() {

    NMClient *client;
    GMainLoop *loop;
    GError *error;
    NMConnection *connection = strongswan_import_sswan("test.json");
    g_return_val_if_fail(connection != NULL, -1);

#if !GLIB_CHECK_VERSION (2, 35, 0)
    /* Initialize GType system */
	g_type_init ();
#endif

    loop = g_main_loop_new (NULL, FALSE);

    /* Connect to NetworkManager */
    client = nm_client_new (NULL, &error);
    if (!client) {
        g_message ("Error: Could not connect to NetworkManager: %s.", error->message);
        g_error_free (error);
        return 1;
    }

    nm_client_add_connection_async(client, connection, TRUE, NULL, added_cb, loop);

    g_main_loop_run(loop);
    g_object_unref(client);
//
    return 0;
}