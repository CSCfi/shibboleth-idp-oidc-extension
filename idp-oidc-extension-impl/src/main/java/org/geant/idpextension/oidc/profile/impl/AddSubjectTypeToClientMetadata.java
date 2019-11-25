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

import javax.annotation.Nonnull;

import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.openid.connect.sdk.SubjectType;

import net.shibboleth.utilities.java.support.logic.Constraint;

/**
* An action that adds the subject_type to the client metadata.
*/
public class AddSubjectTypeToClientMetadata extends AbstractOIDCClientMetadataPopulationAction {

   /** Class logger. */
   @Nonnull
   private final Logger log = LoggerFactory.getLogger(AddSubjectTypeToClientMetadata.class);

   /** The default {@link SubjectType} if it was not defined in the request. */
   private SubjectType defaultSubjectType;

   /** Constructor. */
   public AddSubjectTypeToClientMetadata() {
       defaultSubjectType = SubjectType.PUBLIC;
   }

   /**
    * Set the default {@link SubjectType} to be used if it was not defined in the request.
    * @param subjectType The default {@link SubjectType} to be used if it was not defined in the request.
    */
   public void setDefaultSubjectType(final SubjectType subjectType) {
       defaultSubjectType = Constraint.isNotNull(subjectType, "The default subjectType cannot be null");
   }

   /** {@inheritDoc} */
   @Override
   protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
       final SubjectType requestedType = getInputMetadata().getSubjectType();
       if (requestedType == null) {
           log.debug("{} No subject type requested, using default {}", getLogPrefix(), defaultSubjectType);
           getOutputMetadata().setSubjectType(defaultSubjectType);
       } else {
           //TODO: should be configurable which ones are allowed and to whom
           getOutputMetadata().setSubjectType(requestedType);
       }
   }

}