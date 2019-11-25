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