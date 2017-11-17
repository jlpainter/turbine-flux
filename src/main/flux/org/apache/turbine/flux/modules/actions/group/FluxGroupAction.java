package org.apache.turbine.flux.modules.actions.group;

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

import org.apache.commons.configuration.Configuration;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.fulcrum.security.SecurityService;
import org.apache.fulcrum.security.entity.Group;
import org.apache.fulcrum.security.util.EntityExistsException;
import org.apache.fulcrum.security.util.UnknownEntityException;
import org.apache.fulcrum.yaafi.framework.util.StringUtils;
import org.apache.turbine.annotation.TurbineConfiguration;
import org.apache.turbine.annotation.TurbineService;
import org.apache.turbine.flux.modules.actions.FluxAction;
import org.apache.turbine.pipeline.PipelineData;
import org.apache.turbine.util.RunData;
import org.apache.velocity.context.Context;

/**
 * Action to manage groups in Turbine.
 * 
 */
public class FluxGroupAction extends FluxAction {

	private static Log log = LogFactory.getLog(FluxGroupAction.class);

	/** Injected service instance */
	@TurbineService
	private SecurityService security;

	/** Injected configuration instance */
	@TurbineConfiguration
	private Configuration conf;

	/**
	 * ActionEvent responsible for inserting a new user into the Turbine security
	 * system.
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
		Group group = security.getGroupManager().getGroupInstance();
		data.getParameters().setProperties(group);

		String name = data.getParameters().getString("name");
		group.setName(name);

		try {
			security.getGroupManager().addGroup(group);
		} catch (EntityExistsException eee) {
			context.put("name", name);
			context.put("errorTemplate", "/screens/admin/group/GroupAlreadyExists.vm");
			context.put("group", group);
			/*
			 * We are still in insert mode. So keep this value alive.
			 */
			data.getParameters().add("mode", "insert");
			setTemplate(data, "/admin/group/GroupForm.vm");
		}

	}

	/**
	 * Update a group name
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
		Group group = security.getGroupManager().getGroupByName(data.getParameters().getString("name"));
		data.getParameters().setProperties(group);
		String name = data.getParameters().getString("new_name");
		if (!StringUtils.isEmpty(name)) {
			try {
				security.getGroupManager().renameGroup(group, name);
			} catch (UnknownEntityException uee) {
				/*
				 * Should do something here but I still think we should use the an id so that
				 * this can't happen.
				 */
			}
		} else {
			log.error("Cannot update group to empty name");
		}
	}

	/**
	 * ActionEvent responsible for removing a user.
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
		Group group = security.getGroupManager().getGroupByName(data.getParameters().getString("name"));
		data.getParameters().setProperties(group);
		try {
			security.getGroupManager().removeGroup(group);
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
