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

package org.geant.idpextension.oidc.decoding.impl;

import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import com.nimbusds.oauth2.sdk.http.HTTPRequest;

public class RequestUtil {

    /**
     * Helper method to print request to string for logging.
     * 
     * @param httpReq request to be printed
     * @return request as formatted string.
     */
    public static String toString(HTTPRequest httpReq) {
        if (httpReq == null) {
            return null;
        }
        String nl = System.lineSeparator();
        String ret = httpReq.getMethod().toString() + nl;
        Map<String, List<String>> headers = httpReq.getHeaderMap();
        if (headers != null) {
            ret += "Headers:" + nl;
            for (Entry<String, List<String>> entry : headers.entrySet()) {
                ret += "\t" + entry.getKey() + ":" + entry.getValue() + nl;
            }
        }
        Map<String, List<String>> parameters = httpReq.getQueryParameters();
        if (parameters != null) {
            ret += "Parameters:" + nl;
            for (Entry<String, List<String>> entry : parameters.entrySet()) {
                ret += "\t" + entry.getKey() + ":" + entry.getValue().get(0) + nl;
            }
        }
        return ret;
    }
}
