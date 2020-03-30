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

package org.geant.idpextension.oidc.metadata.impl;

import org.geant.idpextension.oidc.metadata.resolver.RemoteJwkSetCache;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.FileSystemResource;

import java.io.File;
import java.nio.file.Path;
import java.util.Map;
import java.util.Timer;

public class DirectoryWatcherPathEventListener implements DirectoryWatcherEventListener<Path> {

	/**
	 * Class logger.
	 */
	private final Logger log = LoggerFactory.getLogger(DirectoryWatcherPathEventListener.class);

	private final Map<String, FilesystemClientInformationResolver> map;

	private final RemoteJwkSetCache remoteJwkSetCache;
	private final Timer backgroundTaskTimer;
	private final long keyFetchInterval;

	/**
	 *
	 * @param map the map to modify
	 * @param remoteJwkSetCache
	 * @param backgroundTaskTimer
	 * @param keyFetchInterval
	 */
	DirectoryWatcherPathEventListener(final Map<String, FilesystemClientInformationResolver> map,
	                                  final RemoteJwkSetCache remoteJwkSetCache,
	                                  final Timer backgroundTaskTimer,
	                                  final long keyFetchInterval) {
		this.map = map;
		this.remoteJwkSetCache = remoteJwkSetCache;
		this.backgroundTaskTimer = backgroundTaskTimer;
		this.keyFetchInterval = keyFetchInterval;
	}

	@Override
	public void onCreate(final Path path) {
		log.debug("Adding FilesystemClientInformationResolver for metadata file '" + path + "'");

		final String id = path.toString();
		try {
			final FilesystemClientInformationResolver resolver = new FilesystemClientInformationResolver(backgroundTaskTimer, new FileSystemResource(new File(id)));
			resolver.setRemoteJwkSetCache(remoteJwkSetCache);
			resolver.setKeyFetchInterval(keyFetchInterval);
			resolver.setId(id);
			resolver.initialize();
			map.put(id, resolver);
		} catch (final Exception e) {
			e.printStackTrace();
		}
	}

	@Override
	public void onModify(final Path path) {
		log.debug("Updating FilesystemClientInformationResolver for metadata file '" + path + "'");
		onDelete(path);
		onCreate(path);
	}

	@Override
	public void onDelete(final Path path) {
		log.debug("Removing FilesystemClientInformationResolver for metadata file '" + path + "'");

		final String id = path.toString();
		final FilesystemClientInformationResolver resolver = map.remove(id);
		resolver.destroy();
	}
}
