#include <assert.h>
#include "../lib/ntlmssp.c"

int main(void)
{
        struct smb2_context *smb2 = smb2_init_context();
        struct auth_data *auth;
        unsigned char *output;
        uint16_t length;
        char challenge[8] = {0};
        char *long_name = malloc((size_t)UINT16_MAX + 2);
        int wrap;
        assert(smb2 && long_name);
        for (wrap = 0; wrap <= 1; ++wrap) {
                auth = ntlmssp_init_context("user", "password", "domain", "host", challenge);
                assert(auth);
                ntlmssp_set_spnego_wrapping(auth, wrap);
                assert(ntlmssp_generate_blob(NULL, smb2, 0, auth, NULL, 0, &output, &length) == 0);
                assert(output && length > 0);
                ntlmssp_destroy_context(auth);
        }
        auth = ntlmssp_init_context("user", "password", "domain", "host", challenge);
        assert(auth);
        assert(encode_ntlm_challenge(smb2, auth) == 0);
        assert(auth->target_info_len > 0);
        /* Reject impossible allocation sizes without reading the supplied buffer. */
        assert(ntlm_decode_challenge_message(smb2, auth, (unsigned char *)challenge, SIZE_MAX) == -1);
        ntlmssp_destroy_context(auth);

        memset(long_name, 'a', (size_t)UINT16_MAX + 1);
        long_name[(size_t)UINT16_MAX + 1] = 0;
        auth = ntlmssp_init_context("user", "password", "domain", long_name, challenge);
        assert(auth);
        assert(encode_ntlm_challenge(smb2, auth) == -1);
        ntlmssp_destroy_context(auth);
        free(long_name);
        smb2_destroy_context(smb2);
        puts("NTLM normal messages and oversized lengths: PASS");
        return 0;
}
