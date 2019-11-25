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

package org.geant.idpextension.oidc.profile.impl;

import org.geant.idpextension.oidc.messaging.JSONErrorResponse;
import org.opensaml.profile.context.EventContext;
import org.opensaml.profile.context.ProfileRequestContext;
import com.nimbusds.oauth2.sdk.ErrorObject;

/**
 * This action reads an event from the configured {@link EventContext} lookup strategy, constructs a json error response
 * message and attaches it as the outbound message.
 */
public class BuildJSONErrorResponseFromEvent extends AbstractBuildErrorResponseFromEvent<JSONErrorResponse> {

    @SuppressWarnings("rawtypes")
    @Override
    protected JSONErrorResponse buildErrorResponse(ErrorObject error, ProfileRequestContext profileRequestContext) {
        return new JSONErrorResponse(error);
    }

}
