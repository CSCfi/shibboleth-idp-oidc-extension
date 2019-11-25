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

package org.geant.idpextension.oauth2.profile.impl;

import org.geant.idpextension.oidc.profile.impl.AbstractInitializeOutboundResponseMessageContext;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.profile.context.ProfileRequestContext;

import com.nimbusds.oauth2.sdk.Response;

/**
 * Action that adds an outbound {@link MessageContext} and related OIDC contexts to the {@link ProfileRequestContext}
 * not knowing the relying party yet.
 *
 * @event {@link org.opensaml.profile.action.EventIds#PROCEED_EVENT_ID}
 */
public class InitializeOutboundRevokeTokenResponseMessageContext
        extends AbstractInitializeOutboundResponseMessageContext<Response> {

}