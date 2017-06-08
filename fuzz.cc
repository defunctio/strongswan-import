#include <cstdint>
#include <cstdlib>
#include "strongswan_profile.hh"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    GError *error = NULL;
    strongswan_fuzz_import((const char*)Data, Size, &error);
    if(error) {
        g_message("%s", error->message);
        g_error_free(error);
        return 0;
    }
    return 0;
}
