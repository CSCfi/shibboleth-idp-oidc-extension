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
