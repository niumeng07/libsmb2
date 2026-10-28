#include <assert.h>
#include "../lib/libsmb2-dcerpc.c"

static int visited;
static int union_body(char *name _U_, struct dcerpc_context *ctx _U_,
                      struct dcerpc_pdu *pdu _U_, struct dcerpc_iovec *iov _U_,
                      int *offset _U_, void *ptr _U_)
{
        ++visited;
        return 0;
}

int main(void)
{
        struct dcerpc_context ctx = {0};
        struct dcerpc_pdu pdu = {0};
        uint8_t buffer[16] = {0};
        struct dcerpc_iovec iov = {.buf = buffer, .len = sizeof(buffer)};
        uint64_t value;
        uint32_t discriminator;
        int offset;
        ndr_set_endian(&pdu, 1);
        pdu.direction = DCERPC_ENCODE;
        pdu.is_conformance_run = 1;
        value = UINT32_MAX;
        offset = 0;
        assert(ndr_conformance_coder(&ctx, &pdu, &iov, &offset, &value) == 0);
        assert(offset == 4 && buffer[0] == 0xff && buffer[3] == 0xff);
        value = (uint64_t)UINT32_MAX + 1;
        offset = 0;
        assert(ndr_conformance_coder(&ctx, &pdu, &iov, &offset, &value) == -1);
        assert(offset == 0);
        ctx.tctx_id = 1;
        assert(ndr_conformance_coder(&ctx, &pdu, &iov, &offset, &value) == 0);
        assert(offset == 8);

        pdu.is_conformance_run = 0;
        pdu.direction = DCERPC_DECODE;
        offset = 0;
        discriminator = 7;
        assert(ndr_union_coder("", &ctx, &pdu, &iov, &offset,
                               &discriminator, NULL, union_body) == -1);
        assert(discriminator == 7 && visited == 0);
        memset(buffer, 0, sizeof(buffer));
        memset(buffer, 0xff, 4);
        offset = 0;
        assert(ndr_union_coder("", &ctx, &pdu, &iov, &offset,
                               &discriminator, NULL, union_body) == 0);
        assert(discriminator == UINT32_MAX && visited == 1);
        assert((uint32_t)dcerpc_get_switch_is(&pdu) == UINT32_MAX);
        puts("NDR32/NDR64 narrowing boundaries: PASS");
        return 0;
}
