// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Internal handshake token shared between the DKIM verifier (mail-dkim) and
 * the ARC verifier (mail-auth). b.mail.arc.verify validates an
 * ARC-Message-Signature by reusing the DKIM verifier against a synthetic
 * message; this Symbol, set on the verify-options object, tells the DKIM
 * verifier that the signature is an AMS — its i= is an RFC 8617 §4.1.2
 * instance number (not a DKIM AUID), and its signature header is canonicalized
 * under ARC-Message-Signature rather than DKIM-Signature.
 *
 * It lives in its OWN module, exported from neither primitive's public surface,
 * so the reuse signal is unreachable from b.mail.dkim / b.mail.arc. A caller of
 * the public b.mail.dkim.verify cannot obtain it, so the RFC 6376 §3.5 AUID/d=
 * binding check stays a non-opt-out default on real DKIM verification — the
 * reuse is available only to framework code that requires this module directly.
 */

module.exports = Symbol("blamejs.mail.arcAmsReuse");
