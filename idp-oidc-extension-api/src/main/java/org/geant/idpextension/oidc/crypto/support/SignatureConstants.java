/*
 * GÉANT BSD Software License
 *
 * Copyright (c) 2017 - 2020, GÉANT
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
 * following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following
 * disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
 * following disclaimer in the documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the GÉANT nor the names of its contributors may be used to endorse or promote products
 * derived from this software without specific prior written permission.
 *
 * Disclaimer:
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package org.geant.idpextension.oidc.crypto.support;

/** Algorithm Header Parameter Values for JWS. */
public final class SignatureConstants {

    /** Signature - Required HS256. */
    public static final String ALGO_ID_SIGNATURE_HS_256 = "HS256";

    /** Signature - Optional HS384. */
    public static final String ALGO_ID_SIGNATURE_HS_384 = "HS384";

    /** Signature - Optional HS512. */
    public static final String ALGO_ID_SIGNATURE_HS_512 = "HS512";

    /** Signature - Recommended RS256. */
    public static final String ALGO_ID_SIGNATURE_RS_256 = "RS256";

    /** Signature - Optional RS384. */
    public static final String ALGO_ID_SIGNATURE_RS_384 = "RS384";

    /** Signature - Optional RS512. */
    public static final String ALGO_ID_SIGNATURE_RS_512 = "RS512";

    /** Signature - Recommended+ ES256. */
    public static final String ALGO_ID_SIGNATURE_ES_256 = "ES256";

    /** Signature - Optional ES384. */
    public static final String ALGO_ID_SIGNATURE_ES_384 = "ES384";

    /** Signature - Optional ES512. */
    public static final String ALGO_ID_SIGNATURE_ES_512 = "ES512";

    /** Signature - Optional PS256. */
    public static final String ALGO_ID_SIGNATURE_PS_256 = "PS256";

    /** Signature - Optional PS384. */
    public static final String ALGO_ID_SIGNATURE_PS_384 = "PS384";

    /** Signature - Optional PS512. */
    public static final String ALGO_ID_SIGNATURE_PS_512 = "PS512";

    /** No Signature. */
    public static final String ALGO_ID_SIGNATURE_NONE = "none";

    /**
     * Constructor.
     */
    private SignatureConstants() {
        // no op
    }
}
