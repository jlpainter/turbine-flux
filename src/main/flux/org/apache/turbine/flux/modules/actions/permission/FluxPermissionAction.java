package org.apache.turbine.flux.modules.actions.permission;

import org.apache.commons.configuration.Configuration;

/*
 * Copyright 2001-2017 The Apache Software Foundation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License")
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.fulcrum.security.entity.Permission;
import org.apache.fulcrum.security.util.EntityExistsException;
import org.apache.fulcrum.security.util.UnknownEntityException;
import org.apache.fulcrum.yaafi.framework.util.StringUtils;
import org.apache.turbine.annotation.TurbineConfiguration;
import org.apache.turbine.annotation.TurbineService;
import org.apache.turbine.flux.modules.actions.FluxAction;
import org.apache.turbine.pipeline.PipelineData;
import org.apache.turbine.services.security.SecurityService;
import org.apache.turbine.util.RunData;
import org.apache.velocity.context.Context;

/**
 * Action to manage permissions in Turbine.
 * 
 * @version $Id: FluxPermissionAction.java,v 1.11 2017/11/16 10:24:41 painter
 *          Exp $
 */
public class FluxPermissionAction extends FluxAction {
	private static Log log = LogFactory.getLog(FluxPermissionAction.class);

	/** Injected service instance */
	@TurbineService
	private SecurityService security;

	/** Injected configuration instance */
	@TurbineConfiguration
	private Configuration conf;

	/**
	 * ActionEvent responsible for inserting a new permission into the Turbine
	 * security system.
	 * 
	 * @param data
	 *            Turbine information.
	 * @param context
	 *            Context for web pages.
	 * @exception Exception
	 *                a generic exception.
	 */
	public void doInsert(PipelineData pipelineData, Context context) throws Exception {

		RunData data = getRunData(pipelineData);
		Permission permission = security.getPermissionInstance();
		String name = data.getParameters().getString("name");
		permission.setName(name);

		try {
			security.addPermission(permission);
		} catch (EntityExistsException eee) {
			context.put("name", name);
			context.put("errorTemplate", "/screens/permission/FluxPermissionAlreadyExists.vm");
			context.put("permission", permission);
			/*
			 * We are still in insert mode. So keep this value alive.
			 */
			data.getParameters().add("mode", "insert");
			setTemplate(data, "/permission/FluxPermissionForm.vm");
		}

	}

	/**
	 * ActionEvent responsible updating a permission. Must check the input for
	 * integrity before allowing the user info to be update in the database.
	 * 
	 * @param data
	 *            Turbine information.
	 * @param context
	 *            Context for web pages.
	 * @exception Exception
	 *                a generic exception.
	 */
	public void doUpdate(PipelineData pipelineData, Context context) throws Exception {
		RunData data = getRunData(pipelineData);
		Permission permission = security.getPermissionByName(data.getParameters().getString("oldName"));
		String name = data.getParameters().getString("name");
		if (!StringUtils.isEmpty(name)) {
			try {
				security.renamePermission(permission, name);
			} catch (UnknownEntityException uee) {
				/*
				 * Should do something here but I still think we should use the an id so that
				 * this can't happen.
				 */
				log.error(uee);
			}
		} else {
			log.error("Cannot update permission to empty name");
		}
	}

	/**
	 * ActionEvent responsible for removing a permission.
	 * 
	 * @param data
	 *            Turbine information.
	 * @param context
	 *            Context for web pages.
	 * @exception Exception
	 *                a generic exception.
	 */
	public void doDelete(PipelineData pipelineData, Context context) throws Exception {
		RunData data = getRunData(pipelineData);
		Permission permission = security.getPermissionByName(data.getParameters().getString("name"));
		try {
			security.removePermission(permission);
		} catch (UnknownEntityException uee) {
			/*
			 * Should do something here but I still think we should use the an id so that
			 * this can't happen.
			 */
			log.error(uee);
		}
	}

	/**
	 * Implement this to add information to the context.
	 *
	 * @param data
	 *            Turbine information.
	 * @param context
	 *            Context for web pages.
	 * @exception Exception
	 *                a generic exception.
	 */
	public void doPerform(PipelineData pipelineData, Context context) throws Exception {
		RunData data = getRunData(pipelineData);
		log.info("Running do perform!");
		data.setMessage("Can't find the requested action!");
	}
}
