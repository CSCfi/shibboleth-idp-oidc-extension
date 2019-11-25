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

import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import junit.framework.Assert;
import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;
import net.minidev.json.parser.ParseException;
import net.shibboleth.utilities.java.support.logic.ConstraintViolationException;

/** Tests for {@link JSONErrorResponse}. */
public class JSONErrorResponseTest {

    private JSONErrorResponse response;

    ErrorObject content;

    @BeforeMethod
    public void init() throws ParseException {
        content = new ErrorObject("errorCode", "errorDescription", HTTPResponse.SC_BAD_REQUEST);
    }

    @Test
    public void testSuccess() throws ParseException {
        response = new JSONErrorResponse(content, "no-store", "no-cache");
        HTTPResponse httpResponse = response.toHTTPResponse();
        Assert.assertEquals(HTTPResponse.SC_BAD_REQUEST, httpResponse.getStatusCode());
        Assert.assertEquals("application/json; charset=UTF-8", httpResponse.getContentType().toString());
        Assert.assertEquals("no-store", httpResponse.getCacheControl());
        Assert.assertEquals("no-cache", httpResponse.getPragma());
        JSONObject parsedContent =
                (JSONObject) new JSONParser(JSONParser.MODE_PERMISSIVE).parse(httpResponse.getContent());
        Assert.assertEquals("errorCode", parsedContent.get("error"));
        Assert.assertEquals("errorDescription", parsedContent.get("error_description"));
    }

    public void testSuccess2() throws ParseException {
        response = new JSONErrorResponse(content);
        HTTPResponse httpResponse = response.toHTTPResponse();
        Assert.assertEquals(HTTPResponse.SC_BAD_REQUEST, httpResponse.getStatusCode());
        Assert.assertEquals("application/json; charset=UTF-8", httpResponse.getContentType().toString());
        Assert.assertNull(httpResponse.getCacheControl());
        Assert.assertNull(httpResponse.getPragma());
        JSONObject parsedContent =
                (JSONObject) new JSONParser(JSONParser.MODE_PERMISSIVE).parse(httpResponse.getContent());
        Assert.assertEquals("errorCode", parsedContent.get("error"));
        Assert.assertEquals("errorDescription", parsedContent.get("error_description"));
    }

    @Test(expectedExceptions = ConstraintViolationException.class)
    public void testFail() throws ParseException {
        response = new JSONErrorResponse(null);
    }
}
