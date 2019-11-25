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

import java.util.List;

import org.geant.idpextension.oidc.messaging.OIDCWebFingerResponse;

/**
 * A simple implementation for {@link OIDCWebFingerResponse}.
 */
public class OIDCWebFingerResponseImpl implements OIDCWebFingerResponse {

    /** The identifier for the target End-User that is the subject of the discovery links. */
    private String subject;
    
    /** The links for services being able to authenticate the target End-User. */
    private List<Link> links;

    /**
     * Constructor.
     *
     * @param sub The identifier for the target End-User that is the subject of the discovery links.
     * @param lnks The links for services being able to authenticate the target End-User.
     */
    public OIDCWebFingerResponseImpl(final String sub, final List<Link> lnks) {
        subject = sub;
        links = lnks;
    }
    
    /** {@inheritDoc} */
    @Override
    public String getSubject() {
        return subject;
    }

    /** {@inheritDoc} */
    @Override
    public List<Link> getLinks() {
        return links;
    }
}
