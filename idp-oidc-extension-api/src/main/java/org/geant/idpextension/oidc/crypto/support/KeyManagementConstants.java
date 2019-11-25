/*
 * Copyright (c) 2017 - 2020, GÉANT
 *
 * Licensed under the Apache License, Version 2.0 (the “License”); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an “AS IS” BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.geant.idpextension.oidc.crypto.support;

/** Algorithm Header Parameter 'alg' Values for JWE as defined by RFC 7518. */
public final class KeyManagementConstants {

    /** Key Transport algorithms i.e. the jwe 'alg' header parameter. */

    /** Encryption - Recommended- RSAES-PKCS1-v1_5. */
    public static final String ALGO_ID_ALG_RSA_1_5 = "RSA1_5";

    /** Encryption - Recommended+ RSAES OAEP using default parameters. */
    public static final String ALGO_ID_ALG_RSA_OAEP = "RSA-OAEP";

    /** Encryption - Optional RSAES OAEP using SHA-256 and MGF1 with SHA-256. */
    public static final String ALGO_ID_ALG_RSA_OAEP_256 = "RSA-OAEP-256";

    /** Encryption - Recommended AES Key Wrap with default initial value using 128-bit key. */
    public static final String ALGO_ID_ALG_AES_128_KW = "A128KW";

    /** Encryption - Optional AES Key Wrap with default initial value using 192-bit key. */
    public static final String ALGO_ID_ALG_AES_192_KW = "A192KW";

    /** Encryption - Recommended AES Key Wrap with default initial value using 256-bit key. */
    public static final String ALGO_ID_ALG_AES_256_KW = "A256KW";

    /** Encryption - Recommended Direct use of a shared symmetric key as the CEK. */
    public static final String ALGO_ID_ALG_DIR = "dir";

    /** Encryption - Recommended+ Elliptic Curve Diffie-Helman Ephemeral Static key agreement. */
    public static final String ALGO_ID_ALG_ECDH_ES = "ECDH-ES";

    /** Encryption - Recommended ECDH-ES using Concat KDF and CEK wrapped with A128KW. */
    public static final String ALGO_ID_ALG_ECDH_ES_AES_128_KW = "ECDH-ES+A128KW";

    /** Encryption - Optional ECDH-ES using Concat KDF and CEK wrapped with A192KW. */
    public static final String ALGO_ID_ALG_ECDH_ES_AES_192_KW = "ECDH-ES+A192KW";

    /** Encryption - Recommended ECDH-ES using Concat KDF and CEK wrapped with A256KW. */
    public static final String ALGO_ID_ALG_ECDH_ES_AES_256_KW = "ECDH-ES+A256KW";

    /** Encryption - Optional key wrapping with AES GCM using 128-bit key. */
    public static final String ALGO_ID_ALG_AES_128_GCM_KW = "A128GCMKW";

    /** Encryption - Optional key wrapping with AES GCM using 192-bit key. */
    public static final String ALGO_ID_ALG_AES_192_GCM_KW = "A192GCMKW";

    /** Encryption - Optional key wrapping with AES GCM using 256-bit key. */
    public static final String ALGO_ID_ALG_AES_256_GCM_KW = "A256GCMKW";

    /** Encryption - Optional PBES2 with HMAC SHA-256 and A128KW wrapping. */
    public static final String ALGO_ID_ALG_PBES2_HS_256_AES_128_KW = "PBES2-HS256+A128KW";

    /** Encryption - Optional PBES2 with HMAC SHA-538 and A192KW wrapping. */
    public static final String ALGO_ID_ALG_PBES2_HS_384_AES_192_KW = "PBES2-HS384+A192KW";

    /** Encryption - Optional PBES2 with HMAC SHA-512 and A256KW wrapping. */
    public static final String ALGO_ID_ALG_PBES2_HS_512_AES_256_KW = "PBES2-HS512+A256KW";

    /**
     * Constructor.
     */
    private KeyManagementConstants() {
        // no op
    }

}