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
import org.opensaml.xmlsec.algorithm.SignatureAlgorithm;

/**
 * Algorithm descriptor for signature algorithm: ES384.
 */
public final class SignatureES384 implements SignatureAlgorithm {

    /** {@inheritDoc} */
    @Nonnull
    public String getKey() {
        return JCAConstants.KEY_ALGO_EC;
    }

    /** {@inheritDoc} */
    @Nonnull
    public String getURI() {
        return SignatureConstants.ALGO_ID_SIGNATURE_ES_384;
    }

    /** {@inheritDoc} */
    @Nonnull
    public AlgorithmType getType() {
        return AlgorithmType.Signature;
    }

    /** {@inheritDoc} */
    @Nonnull
    public String getJCAAlgorithmID() {
        return JCAConstants.SIGNATURE_ECDSA_SHA384;
    }

    /** {@inheritDoc} */
    @Nonnull
    public String getDigest() {
        return JCAConstants.DIGEST_SHA384;
    }

}
