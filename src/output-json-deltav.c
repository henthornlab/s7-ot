/* Copyright (C) 2023 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/*
 * TODO: Update \author in this file and in output-json-deltav.h.
 * TODO: Remove SCLogNotice statements, or convert to debug.
 * TODO: Implement your app-layers logging.
 */

/**
 * \file
 *
 * \author FirstName LastName <yourname@domain>
 *
 * Implement JSON/eve logging app-layer DeltaV.
 */

#include "suricata-common.h"
#include "detect.h"
#include "pkt-var.h"
#include "conf.h"

#include "threads.h"
#include "threadvars.h"
#include "tm-threads.h"

#include "util-unittest.h"
#include "util-buffer.h"
#include "util-debug.h"
#include "util-byte.h"

#include "output.h"
#include "output-json.h"

#include "app-layer.h"
#include "app-layer-parser.h"

#include "output-json-deltav.h"
#include "rust.h"

typedef struct LogDeltaVFileCtx_ {
    uint32_t flags;
    OutputJsonCtx *eve_ctx;
} LogDeltaVFileCtx;

typedef struct LogDeltaVLogThread_ {
    LogDeltaVFileCtx *deltavlog_ctx;
    OutputJsonThreadCtx *ctx;
} LogDeltaVLogThread;

static int JsonDeltaVLogger(ThreadVars *tv, void *thread_data, const Packet *p, Flow *f,
        void *state, void *tx, uint64_t tx_id)
{
    SCLogNotice("JsonDeltaVLogger");
    LogDeltaVLogThread *thread = thread_data;

    JsonBuilder *js =
            CreateEveHeader(p, LOG_DIR_PACKET, "deltav", NULL, thread->deltavlog_ctx->eve_ctx);
    if (unlikely(js == NULL)) {
        return TM_ECODE_FAILED;
    }

    jb_open_object(js, "deltav");
    if (!rs_deltav_logger_log(tx, js)) {
        goto error;
    }
    jb_close(js);

    OutputJsonBuilderBuffer(js, thread->ctx);
    jb_free(js);

    return TM_ECODE_OK;

error:
    jb_free(js);
    return TM_ECODE_FAILED;
}

static void OutputDeltaVLogDeInitCtxSub(OutputCtx *output_ctx)
{
    LogDeltaVFileCtx *deltavlog_ctx = (LogDeltaVFileCtx *)output_ctx->data;
    SCFree(deltavlog_ctx);
    SCFree(output_ctx);
}

static OutputInitResult OutputDeltaVLogInitSub(ConfNode *conf, OutputCtx *parent_ctx)
{
    OutputInitResult result = { NULL, false };
    OutputJsonCtx *ajt = parent_ctx->data;

    LogDeltaVFileCtx *deltavlog_ctx = SCCalloc(1, sizeof(*deltavlog_ctx));
    if (unlikely(deltavlog_ctx == NULL)) {
        return result;
    }
    deltavlog_ctx->eve_ctx = ajt;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(*output_ctx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(deltavlog_ctx);
        return result;
    }
    output_ctx->data = deltavlog_ctx;
    output_ctx->DeInit = OutputDeltaVLogDeInitCtxSub;

    SCLogNotice("DeltaV log sub-module initialized.");

    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_DELTAV);

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

static TmEcode JsonDeltaVLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    LogDeltaVLogThread *thread = SCCalloc(1, sizeof(*thread));
    if (unlikely(thread == NULL)) {
        return TM_ECODE_FAILED;
    }

    if (initdata == NULL) {
        SCLogDebug("Error getting context for EveLogDeltaV.  \"initdata\" is NULL.");
        goto error_exit;
    }

    thread->deltavlog_ctx = ((OutputCtx *)initdata)->data;
    thread->ctx = CreateEveThreadCtx(t, thread->deltavlog_ctx->eve_ctx);
    if (!thread->ctx) {
        goto error_exit;
    }
    *data = (void *)thread;

    return TM_ECODE_OK;

error_exit:
    SCFree(thread);
    return TM_ECODE_FAILED;
}

static TmEcode JsonDeltaVLogThreadDeinit(ThreadVars *t, void *data)
{
    LogDeltaVLogThread *thread = (LogDeltaVLogThread *)data;
    if (thread == NULL) {
        return TM_ECODE_OK;
    }
    FreeEveThreadCtx(thread->ctx);
    SCFree(thread);
    return TM_ECODE_OK;
}

void JsonDeltaVLogRegister(void)
{
    /* Register as an eve sub-module. */
    OutputRegisterTxSubModule(LOGGER_JSON_TX, "eve-log", "JsonDeltaVLog", "eve-log.deltav",
            OutputDeltaVLogInitSub, ALPROTO_DELTAV, JsonDeltaVLogger,
            JsonDeltaVLogThreadInit, JsonDeltaVLogThreadDeinit, NULL);

    SCLogNotice("DeltaV JSON logger registered.");
}
