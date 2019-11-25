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
