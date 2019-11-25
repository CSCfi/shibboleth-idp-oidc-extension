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

package org.geant.idpextension.oidc.messaging;

import java.util.List;

/**
 * An interface for Web Finger responses related to OIDC.
 */
public interface OIDCWebFingerResponse {

    /**
     * Get the identifier for the target End-User that is the subject of the discovery links.
     * @return The identifier for the target End-User that is the subject of the discovery links.
     */
    public String getSubject();
    
    /**
     * Get the links for services being able to authenticate the target End-User.
     * @return The links for services being able to authenticate the target End-User.
     */
    public List<Link> getLinks();
    
    /**
     * An interface for a link in a Web Finger response related to OIDC.
     */
    public interface Link {
        
        /**
         * Get the URI identifying the type of service.
         * @return The URI identifying the type of service.
         */
        public String getRel();
        
        /**
         * Get the link to the service.
         * @return The link to the service.
         */
        public String getHref();
    }
}
