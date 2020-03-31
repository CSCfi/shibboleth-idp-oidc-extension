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

import java.nio.file.Path;

/**
 * Event Handler interface for the {@link DirectoryWatcher}.
 */
public interface DirectoryWatcherEventHandler {

	/**
	 * Handle {@link java.nio.file.StandardWatchEventKinds#ENTRY_CREATE} event.
	 *
	 * @param path the absolute Path of the created file.
	 */
	void onCreate(final Path path);

	/**
	 * Handle {@link java.nio.file.StandardWatchEventKinds#ENTRY_MODIFY} event.
	 *
	 * @param path the absolute Path of the modified file.
	 */
	void onModify(final Path path);

	/**
	 * Handle {@link java.nio.file.StandardWatchEventKinds#ENTRY_DELETE} event.
	 *
	 * @param path the absolute Path of the deleted file.
	 */
	void onDelete(final Path path);
}
