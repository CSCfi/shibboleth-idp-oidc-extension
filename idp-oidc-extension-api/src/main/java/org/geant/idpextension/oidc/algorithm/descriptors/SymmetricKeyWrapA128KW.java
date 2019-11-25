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

import org.geant.idpextension.oidc.crypto.support.KeyManagementConstants;
import org.opensaml.security.crypto.JCAConstants;
import org.opensaml.xmlsec.algorithm.SymmetricKeyWrapAlgorithm;

import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;

/**
 * Algorithm descriptor for JWE key management algorithm: AES128KW.
 * 
 */
public class SymmetricKeyWrapA128KW implements SymmetricKeyWrapAlgorithm {

    /** {@inheritDoc} */
    @Nonnull
    @NotEmpty
    public String getKey() {
        return JCAConstants.KEY_ALGO_AES;
    }

    /** {@inheritDoc} */
    @Nonnull
    @NotEmpty
    public String getURI() {
        return KeyManagementConstants.ALGO_ID_ALG_AES_128_KW;
    }

    /** {@inheritDoc} */
    @Nonnull
    public AlgorithmType getType() {
        return AlgorithmType.SymmetricKeyWrap;
    }

    /** {@inheritDoc} */
    @Nonnull
    public String getJCAAlgorithmID() {
        return JCAConstants.KEYWRAP_ALGO_AES;
    }

    @Override
    public Integer getKeyLength() {
        return 128;
    }

}
