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

package org.geant.idpextension.oauth2.messaging.impl;

import javax.annotation.Nonnull;

import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ErrorResponse;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;

import net.shibboleth.utilities.java.support.logic.Constraint;

/** OAuth2 Token Revocation Error message class. */
public class OAuth2RevocationErrorResponse implements ErrorResponse {

    /** Error Object. */
    ErrorObject errorObject;

    /**
     * Constructor.
     * 
     * @param error Error object the response is based on.
     */
    public OAuth2RevocationErrorResponse(@Nonnull ErrorObject error) {
        Constraint.isNotNull(error, "Error object must not be null");
        errorObject = error;
    }

    /** {@inheritDoc} */
    @Override
    public ErrorObject getErrorObject() {
        return errorObject;
    }

    /** {@inheritDoc} */
    @Override
    public boolean indicatesSuccess() {
        return false;
    }

    /** {@inheritDoc} */
    @Override
    public HTTPResponse toHTTPResponse() {
        HTTPResponse resp = new HTTPResponse(errorObject.getHTTPStatusCode());
        resp.setStatusMessage(errorObject.getDescription());
        return resp;
    }

}
