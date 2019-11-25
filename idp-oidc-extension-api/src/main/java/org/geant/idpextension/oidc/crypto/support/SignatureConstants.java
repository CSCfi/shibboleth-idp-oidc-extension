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
