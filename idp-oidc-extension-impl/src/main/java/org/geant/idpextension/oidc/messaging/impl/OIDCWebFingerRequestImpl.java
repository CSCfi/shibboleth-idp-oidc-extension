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

package org.geant.idpextension.oidc.messaging.impl;

import org.geant.idpextension.oidc.messaging.OIDCWebFingerRequest;

/**
 * A simple implementation for {@link OIDCWebFingerRequest}.
 */
public class OIDCWebFingerRequestImpl implements OIDCWebFingerRequest {
    
    /** The identifier for the target End-User that is the subject of the discovery request. */
    private String resource;
    
    /** The URI identifying the type of service whose location is being requested. */
    private String rel;
    
    /**
     * Constructor.
     *
     * @param resrc The identifier for the target End-User that is the subject of the discovery request.
     * @param rl The URI identifying the type of service whose location is being requested.
     */
    public OIDCWebFingerRequestImpl(final String resrc, final String rl) {
        resource = resrc;
        rel = rl;
    }
    
    /** {@inheritDoc} */
    public String getResource() {
        return resource;
    }
    
    /** {@inheritDoc} */
    public String getRel() {
        return rel;
    }    
}
