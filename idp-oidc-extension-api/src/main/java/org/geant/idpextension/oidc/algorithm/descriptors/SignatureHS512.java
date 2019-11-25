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

package org.geant.idpextension.oidc.algorithm.descriptors;

import javax.annotation.Nonnull;

import org.geant.idpextension.oidc.crypto.support.SignatureConstants;
import org.opensaml.security.crypto.JCAConstants;
import org.opensaml.xmlsec.algorithm.MACAlgorithm;

/**
 * Algorithm descriptor for HMAC algorithm: HS512.
 */
public final class SignatureHS512 implements MACAlgorithm {

    /** {@inheritDoc} */
    @Nonnull
    public String getURI() {
        return SignatureConstants.ALGO_ID_SIGNATURE_HS_512;
    }

    /** {@inheritDoc} */
    @Nonnull
    public AlgorithmType getType() {
        return AlgorithmType.Mac;
    }

    /** {@inheritDoc} */
    @Nonnull
    public String getJCAAlgorithmID() {
        return JCAConstants.HMAC_SHA512;
    }

    /** {@inheritDoc} */
    @Nonnull
    public String getDigest() {
        return JCAConstants.DIGEST_SHA512;
    }

}
