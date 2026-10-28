/* Exercise the production receive-length helpers and lease wire encoding. */
#include <assert.h>
#include "../lib/socket.c"
#include "../lib/smb2-cmd-oplock-break.c"

static void test_padding(void)
{
        struct smb2_context smb2 = {0};
        unsigned char encrypted = 0;
        assert(smb2_remaining_length(64, 64) == 0);
        assert(smb2_remaining_length(64, 65) == -1);
        assert(smb2_remaining_length(SIZE_MAX, 0) == -1);
        assert(smb2_remaining_length(SMB2_MAX_PDU_SIZE, 0) == SMB2_MAX_PDU_SIZE);
        assert(smb2_remaining_length((size_t)SMB2_MAX_PDU_SIZE + 1, 0) == -1);
        smb2.spl = 64;
        smb2.in.num_done = 68;
        assert(smb2_padding_length(&smb2) == 0);
        smb2.enc = &encrypted;
        smb2.in.num_done = 64;
        assert(smb2_padding_length(&smb2) == 0);
        smb2.hdr.next_command = 104;
        smb2.payload_offset = 64;
        smb2.in.num_done = 100;
        assert(smb2_padding_length(&smb2) == 4);
        smb2.in.num_done = 105;
        assert(smb2_padding_length(&smb2) == -1);
        smb2.in.num_done = 63;
        assert(smb2_padding_length(&smb2) == -1);
        smb2.hdr.next_command = 32;
        assert(smb2_padding_length(&smb2) == -1);
}

static void test_lease_encoding(struct smb2_context *smb2)
{
        struct smb2_lease_break_acknowledgement ack = {0};
        struct smb2_lease_break_reply reply = {0};
        struct smb2_pdu *pdu;
        struct smb2_iovec *iov;
        uint32_t state, flags;
        uint64_t duration;
        int i;

        ack.lease_state = 3;
        /* Synthetic nonzero reserved fields detect truncation/overlap in the codec. */
        ack.flags = 0x12345678;
        ack.lease_duration = UINT64_C(0x1122334455667788);
        for (i = 0; i < SMB2_LEASE_KEY_SIZE; ++i) ack.lease_key[i] = (uint8_t)i;
        pdu = smb2_cmd_lease_break_async(smb2, &ack, NULL, NULL);
        assert(pdu);
        iov = &pdu->out.iov[1];
        smb2_get_uint32(iov, 4, &flags);
        smb2_get_uint32(iov, 24, &state);
        smb2_get_uint64(iov, 28, &duration);
        assert(flags == ack.flags && state == ack.lease_state);
        assert(duration == ack.lease_duration);
        assert(memcmp(iov->buf + 8, ack.lease_key, SMB2_LEASE_KEY_SIZE) == 0);
        smb2_free_pdu(smb2, pdu);

        reply.lease_state = ack.lease_state;
        reply.lease_duration = ack.lease_duration;
        pdu = smb2_cmd_lease_break_reply_async(smb2, &reply, NULL, NULL);
        assert(pdu);
        iov = &pdu->out.iov[1];
        smb2_get_uint32(iov, 24, &state);
        smb2_get_uint64(iov, 28, &duration);
        assert(state == reply.lease_state && duration == reply.lease_duration);
        smb2_free_pdu(smb2, pdu);
}

int main(void)
{
        struct smb2_context *smb2 = smb2_init_context();
        assert(smb2);
        test_padding();
        test_lease_encoding(smb2);
        smb2_destroy_context(smb2);
        puts("Receive lengths and lease encoding: PASS");
        return 0;
}
