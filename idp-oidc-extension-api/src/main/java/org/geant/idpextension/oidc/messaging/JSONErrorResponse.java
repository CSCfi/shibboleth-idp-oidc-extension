/*
 * GÉANT BSD Software License
 *
 * Copyright (c) 2017 - 2020, GÉANT
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
 * following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following
 * disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
 * following disclaimer in the documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the GÉANT nor the names of its contributors may be used to endorse or promote products
 * derived from this software without specific prior written permission.
 *
 * Disclaimer:
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package org.geant.idpextension.oidc.messaging;

import javax.annotation.Nonnull;

import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ErrorResponse;
import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;

import net.minidev.json.JSONObject;
import net.shibboleth.utilities.java.support.logic.Constraint;

/** Class for creating JSON Error response for requests expecting JSON response. */
public class JSONErrorResponse implements ErrorResponse {

    /** Error object. */
    ErrorObject error;

    /** cache control value. */
    String cacheControl;

    /** pragma value. */
    String pragma;

    /**
     * Constructor.
     * 
     * @param errorObject error. MUST not be null.
     */
    public JSONErrorResponse(@Nonnull ErrorObject errorObject) {
        this(errorObject, null, null);
    }

    /**
     * Constructor.
     * 
     * @param contentObject JSON content. MUST not be null.
     * @param cacheControlValue cache control value.
     * @param pragmaValue pragma value.
     */
    public JSONErrorResponse(@Nonnull ErrorObject errorObject, String cacheControlValue, String pragmaValue) {
        Constraint.isNotNull(errorObject, "content cannot be null");
        error = errorObject;
        cacheControl = cacheControlValue;
        pragma = pragmaValue;
    }

    @Override
    public boolean indicatesSuccess() {
        return true;
    }

    /**
     * Error content as json.
     * 
     * @return error as json.
     */
    private String getContent() {
        JSONObject content = new JSONObject();
        if (error == null)
            return null;
        content.put("error", error.getCode());
        if (error.getDescription() != null)
            content.put("error_description", error.getDescription());
        if (error.getURI() != null)
            content.put("error_uri", error.getURI().toString());
        return content.toString();
    }

    @Override
    public HTTPResponse toHTTPResponse() {
        HTTPResponse httpResponse = new HTTPResponse(error.getHTTPStatusCode());
        httpResponse.setContentType(CommonContentTypes.APPLICATION_JSON);
        if (cacheControl != null) {
            httpResponse.setCacheControl(cacheControl);
        }
        if (pragma != null) {
            httpResponse.setPragma(pragma);
        }
        httpResponse.setContent(getContent());
        return httpResponse;
    }

    @Override
    public ErrorObject getErrorObject() {
        return error;
    }
}
