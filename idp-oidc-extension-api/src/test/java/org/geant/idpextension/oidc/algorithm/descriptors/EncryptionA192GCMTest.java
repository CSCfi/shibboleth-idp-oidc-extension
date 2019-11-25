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

package org.geant.idpextension.oidc.algorithm.descriptors;

import junit.framework.Assert;

import org.geant.idpextension.oidc.crypto.support.EncryptionConstants;
import org.opensaml.security.crypto.JCAConstants;
import org.opensaml.xmlsec.algorithm.AlgorithmDescriptor.AlgorithmType;
import org.testng.annotations.Test;

/**
 * Unit tests for {@link EncryptionA192GCM}
 */
public class EncryptionA192GCMTest {

	private EncryptionA192GCM algorithm = new EncryptionA192GCM();

	@Test
	public void testInitialState() {
		Assert.assertEquals(JCAConstants.KEY_ALGO_AES, algorithm.getKey());
		Assert.assertEquals(EncryptionConstants.ALGO_ID_ENC_ALG_A192GCM, algorithm.getURI());
		Assert.assertEquals(AlgorithmType.BlockEncryption, algorithm.getType());
		Assert.assertEquals("AES/GCM/NoPadding", algorithm.getJCAAlgorithmID());
		Assert.assertEquals(new Integer(192), algorithm.getKeyLength());
		Assert.assertEquals(JCAConstants.CIPHER_MODE_GCM, algorithm.getCipherMode());
		Assert.assertEquals(JCAConstants.CIPHER_PADDING_NONE, algorithm.getPadding());
	}

}