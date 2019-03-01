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

import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import junit.framework.Assert;
import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;
import net.minidev.json.parser.ParseException;
import net.shibboleth.utilities.java.support.logic.ConstraintViolationException;

/** Tests for JSONSuccessResponse. */
public class JSONSuccessResponseTest {

    JSONSuccessResponse response;

    JSONObject content;

    @BeforeMethod
    public void init() throws ParseException {
        content = new JSONObject();
        content.put("field1", "value1");
        content.put("field2", "value2");
    }

    @Test
    public void testSuccess() throws ParseException {
        response = new JSONSuccessResponse(content, "no-store", "no-cache");
        HTTPResponse httpResponse = response.toHTTPResponse();
        Assert.assertEquals(HTTPResponse.SC_OK, httpResponse.getStatusCode());
        Assert.assertEquals("application/json; charset=UTF-8", httpResponse.getContentType().toString());
        Assert.assertEquals("no-store", httpResponse.getCacheControl());
        Assert.assertEquals("no-cache", httpResponse.getPragma());
        JSONObject parsedContent =
                (JSONObject) new JSONParser(JSONParser.MODE_PERMISSIVE).parse(httpResponse.getContent());
        Assert.assertEquals(content.get("field1"), parsedContent.get("field1"));
        Assert.assertEquals(content.get("field2"), parsedContent.get("field2"));
    }

    @Test
    public void testSuccess2() throws ParseException {
        response = new JSONSuccessResponse(content);
        HTTPResponse httpResponse = response.toHTTPResponse();
        Assert.assertEquals(HTTPResponse.SC_OK, httpResponse.getStatusCode());
        Assert.assertEquals("application/json; charset=UTF-8", httpResponse.getContentType().toString());
        Assert.assertNull(httpResponse.getCacheControl());
        Assert.assertNull(httpResponse.getPragma());
        JSONObject parsedContent =
                (JSONObject) new JSONParser(JSONParser.MODE_PERMISSIVE).parse(httpResponse.getContent());
        Assert.assertEquals(content.get("field1"), parsedContent.get("field1"));
        Assert.assertEquals(content.get("field2"), parsedContent.get("field2"));
    }

    @Test(expectedExceptions = ConstraintViolationException.class)
    public void testFail() throws ParseException {
        response = new JSONSuccessResponse(null);

    }
}
