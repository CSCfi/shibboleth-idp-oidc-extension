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

import org.geant.idpextension.oidc.messaging.OIDCWebFingerResponse.Link;

/**
 * A simple implementation for {@link Link}.
 */
public class OIDCWebFingerResponseLinkImpl implements Link {


    /** The URI identifying the type of service. */
    private String rel;
        
    /** The link to the service. */
    private String href;
        
    /**
     * Constructor.
     *
     * @param rl The URI identifying the type of service.
     * @param ref The link to the service.
     */
    public OIDCWebFingerResponseLinkImpl(final String rl, final String ref) {
        rel = rl;
        href = ref;
    }
        
    /** {@inheritDoc} */
    @Override
    public String getRel() {
        return rel;
    }

    /** {@inheritDoc} */
    @Override
    public String getHref() {
        return href;
    }
}
