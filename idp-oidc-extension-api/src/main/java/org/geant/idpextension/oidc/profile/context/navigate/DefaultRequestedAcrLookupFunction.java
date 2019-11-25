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

package org.geant.idpextension.oidc.profile.context.navigate;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;
import javax.annotation.Nonnull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.claims.ACR;

/**
 * A function that returns copy of requested acr values via a lookup function. This default lookup locates acr values
 * from oidc authentication request if available. If information is not available, null is returned. If there are acr
 * values in request object it is used instead of acr_values parameter.
 */
public class DefaultRequestedAcrLookupFunction extends AbstractAuthenticationRequestLookupFunction<List<ACR>> {

    /** Class logger. */
    @Nonnull
    private Logger log = LoggerFactory.getLogger(DefaultRequestedAcrLookupFunction.class);

    /** {@inheritDoc} */
    @Override
    List<ACR> doLookup(@Nonnull AuthenticationRequest req) {
        try {
            if (requestObject != null && requestObject.getJWTClaimsSet().getClaim("acr_values") != null) {
                List<ACR> reqObjectAcr = new ArrayList<ACR>();
                String[] acrs = ((String) requestObject.getJWTClaimsSet().getClaim("acr_values")).split(" ");
                for (String acr : acrs) {
                    reqObjectAcr.add(new ACR(acr));
                }
                return reqObjectAcr;
            }
        } catch (ParseException e) {
            log.error("Unable to parse acr values from request object acr_values value");
            return null;
        }
        if (req.getACRValues() == null) {
            return null;
        }
        List<ACR> requestParameterAcr = new ArrayList<ACR>();
        requestParameterAcr.addAll(req.getACRValues());
        return requestParameterAcr;
    }
}