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

import com.nimbusds.oauth2.sdk.SuccessResponse;
import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;

import net.minidev.json.JSONObject;
import net.shibboleth.utilities.java.support.logic.Constraint;

/** Class for creating JSON Success response. */
public class JSONSuccessResponse implements SuccessResponse {

    /** JSON content. */
    JSONObject content;

    /** cache control value. */
    String cacheControl;

    /** pragma value. */
    String pragma;

    /**
     * Constructor.
     * 
     * @param contentObject JSON content. MUST not be null.
     */
    public JSONSuccessResponse(@Nonnull JSONObject contentObject) {
        this(contentObject, null, null);

    }

    /**
     * Constructor.
     * 
     * @param contentObject JSON content. MUST not be null.
     * @param cacheControlValue cache control value.
     * @param pragmaValue pragma value.
     */
    public JSONSuccessResponse(@Nonnull JSONObject contentObject, String cacheControlValue, String pragmaValue) {
        Constraint.isNotNull(contentObject, "content cannot be null");
        content = contentObject;
        cacheControl = cacheControlValue;
        pragma = pragmaValue;
    }

    @Override
    public boolean indicatesSuccess() {
        return true;
    }

    @Override
    public HTTPResponse toHTTPResponse() {
        HTTPResponse httpResponse = new HTTPResponse(HTTPResponse.SC_OK);
        httpResponse.setContentType(CommonContentTypes.APPLICATION_JSON);
        if (cacheControl != null) {
            httpResponse.setCacheControl(cacheControl);
        }
        if (pragma != null) {
            httpResponse.setPragma(pragma);
        }
        httpResponse.setContent(content.toJSONString());
        return httpResponse;
    }
}
