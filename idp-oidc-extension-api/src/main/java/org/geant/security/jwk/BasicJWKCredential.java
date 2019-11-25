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

package org.geant.security.jwk;

import org.opensaml.security.credential.BasicCredential;
import com.nimbusds.jose.Algorithm;

/**
 * A basic implementation of {@link JWKCredential}.
 */
public class BasicJWKCredential extends BasicCredential implements JWKCredential {

    /** jwk algorithm. */
    private Algorithm jwkAlgorithm;

    /** jwk kid. */
    private String jwkKid;

    /**
     * Set the kid of jwk.
     * 
     * @param kid kid of jwk
     */
    public void setKid(String kid) {
        jwkKid = kid;
    }

    /** {@inheritDoc} */
    @Override
    public String getKid() {
        return jwkKid;
    }

    /**
     * Set the algorithm of jwk.
     * 
     * @param algorithm algorithm of jwk.
     */
    public void setAlgorithm(Algorithm algorithm) {
        jwkAlgorithm = algorithm;
    }

    /** {@inheritDoc} */
    @Override
    public Algorithm getAlgorithm() {
        return jwkAlgorithm;
    }

}
