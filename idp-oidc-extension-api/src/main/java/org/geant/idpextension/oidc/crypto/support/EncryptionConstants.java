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

/** Algorithm Header Parameter 'enc' Values for JWE as defined by RFC 7518. */
public final class EncryptionConstants {

    /** Encryption algorithms i.e. the jwe 'enc' header parameter. */

    /** Encryption - Required- A128CBC-HS256. */
    public static final String ALGO_ID_ENC_ALG_A128CBC_HS256 = "A128CBC-HS256";

    /** Encryption - Optional- A192CBC-HS384. */
    public static final String ALGO_ID_ENC_ALG_A192CBC_HS384 = "A192CBC-HS384";

    /** Encryption -Required- A256CBC-HS512. */
    public static final String ALGO_ID_ENC_ALG_A256CBC_HS512 = "A256CBC-HS512";

    /** Encryption -Recommended- A128GCM. */
    public static final String ALGO_ID_ENC_ALG_A128GCM = "A128GCM";

    /** Encryption -Optional- A192GCM. */
    public static final String ALGO_ID_ENC_ALG_A192GCM = "A192GCM";

    /** Encryption -Recommended- A256GCM. */
    public static final String ALGO_ID_ENC_ALG_A256GCM = "A256GCM";

    /**
     * Constructor.
     */
    private EncryptionConstants() {
        // no op
    }

}