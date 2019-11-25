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

/**
 * An interface for Web Finger requests related to OIDC.
 */
public interface OIDCWebFingerRequest {
    
    /**
     * Get the identifier for the target End-User that is the subject of the discovery request.
     * @return The identifier for the target End-User that is the subject of the discovery request.
     */
    public String getResource();
    
    /**
     * Get the URI identifying the type of service whose location is being requested.
     * @return The URI identifying the type of service whose location is being requested.
     */
    public String getRel();

}
