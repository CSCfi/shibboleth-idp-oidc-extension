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

package org.geant.idpextension.oidc.encoding.impl;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import javax.servlet.http.HttpServletResponse;

import com.nimbusds.oauth2.sdk.http.HTTPResponse;

class ResponseUtil {

    /**
     * Helper method to print response to string for logging.
     * 
     * @param httpResponse response to be printed
     * @return response as formatted string.
     */
    protected static String toString(HTTPResponse httpResponse) {
        if (httpResponse == null) {
            return null;
        }
        String nl = System.lineSeparator();
        String ret = nl;
        Map<String, List<String>> headers = httpResponse.getHeaderMap();
        if (headers != null) {
            ret += "Headers:" + nl;
            for (Entry<String, List<String>> entry : headers.entrySet()) {
                ret += "\t" + entry.getKey() + ":" + entry.getValue().get(0) + nl;
            }
        }
        if (httpResponse.getContent() != null) {
            ret += "Content:" + httpResponse.getContent();
        }
        return ret;
    }

    /**
     * Helper method to print response to string for logging.
     * 
     * @param httpServletResponse response to be printed
     * @return response as formatted string.
     */
    protected static String toString(HttpServletResponse httpServletResponse, String content) {
        if (httpServletResponse == null) {
            return null;
        }
        String nl = System.lineSeparator();
        String ret = nl;
        Collection<String> headerNames = httpServletResponse.getHeaderNames();
        if (headerNames != null) {
            ret += "Headers:" + nl;
            for (String headerName : headerNames) {
                ret += "\t" + headerName + ":" + httpServletResponse.getHeader(headerName) + nl;
            }
        }
        if (content != null) {
            ret += "Content:" + content;
        }
        return ret;
    }

}
