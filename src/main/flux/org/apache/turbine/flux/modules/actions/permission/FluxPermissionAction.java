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
import org.apache.fulcrum.security.entity.Role;
import org.apache.fulcrum.security.torque.om.TurbinePermissionPeer;
import org.apache.fulcrum.security.torque.om.TurbineRolePermissionPeer;
import org.apache.fulcrum.security.util.DataBackendException;
import org.apache.fulcrum.security.util.PermissionSet;
import org.apache.fulcrum.security.util.UnknownEntityException;
import org.apache.fulcrum.yaafi.framework.util.StringUtils;
import org.apache.torque.criteria.Criteria;
import org.apache.turbine.annotation.TurbineConfiguration;
import org.apache.turbine.annotation.TurbineService;
import org.apache.turbine.flux.modules.actions.FluxAction;
import org.apache.turbine.fluxtest.om.TurbinePermission;
import org.apache.turbine.fluxtest.om.TurbineRolePermission;
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
		String role = data.getParameters().getString("role");
		String name = data.getParameters().getString("name");
		if (!StringUtils.isEmpty(name) && !StringUtils.isEmpty(role)) {
			Role tr = security.getRoleByName(role);
			if (tr != null) {
				// create the permission
				TurbinePermission tp = new TurbinePermission();
				tp.setName(name);
				tp.setNew(true);
				tp.save();

				// link role to permission
				TurbineRolePermission trp = new TurbineRolePermission();
				trp.setRoleId((int) tr.getId());
				trp.setPermissionId((int) tp.getPermissionId());
				trp.setNew(true);
				trp.save();
			}
		} else {
			data.setMessage("Cannot add permission with no name");
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
		String roleName = data.getParameters().getString("role");
		String permName = data.getParameters().getString("oldName");
		String newName = data.getParameters().getString("name");

		if (!StringUtils.isEmpty(permName) && !StringUtils.isEmpty(newName) && !StringUtils.isEmpty(roleName)) {

			Role role = security.getRoleByName(roleName);
			Permission permission = getPermission(role, permName);

			if (role != null && permission != null) {
				try {

					// this method is broken and not working, gives data backend exception
					// security.renamePermission(permission, newName);

					// use torque to locate and update the obj
					Criteria criteria = new Criteria();
					criteria.where(TurbinePermissionPeer.PERMISSION_ID, permission.getId());
					org.apache.fulcrum.security.torque.om.TurbinePermission tp = TurbinePermissionPeer
							.doSelectSingleRecord(criteria);
					tp.setName(newName);
					tp.setNew(false);
					tp.setModified(true);
					tp.save();

				} catch (Exception e) {
					log.error("Could not find update permission: " + e);
				}
			}
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
		String roleName = data.getParameters().getString("role");
		String permName = data.getParameters().getString("name");
		if (!StringUtils.isEmpty(permName) && !StringUtils.isEmpty(roleName)) {
			Role role = security.getRoleByName(roleName);
			Permission permission = getPermission(role, permName);

			if (role != null && permission != null) {
				try {

					// remove the role-permission link first
					Criteria criteria = new Criteria();
					criteria.where(TurbineRolePermissionPeer.ROLE_ID, role.getId());
					criteria.where(TurbineRolePermissionPeer.PERMISSION_ID, permission.getId());
					org.apache.fulcrum.security.torque.om.TurbineRolePermission trp = TurbineRolePermissionPeer
							.doSelectSingleRecord(criteria);
					TurbineRolePermissionPeer.doDelete(trp);

					// now remove the permission
					// use torque to locate and update the obj
					criteria = new Criteria();
					criteria.where(TurbinePermissionPeer.PERMISSION_ID, permission.getId());
					org.apache.fulcrum.security.torque.om.TurbinePermission tp = TurbinePermissionPeer
							.doSelectSingleRecord(criteria);
					TurbinePermissionPeer.doDelete(tp);

					// this method is broken
					// security.removePermission(permission);

				} catch (Exception e) {
					log.error("Could not find turbine role-permission link: " + e);
				}
			}
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

	/**
	 * Work around to locate permission associated with a particular role
	 */
	private Permission getPermission(Role role, String name) throws DataBackendException, UnknownEntityException {
		Permission permission = null;
		if (StringUtils.isEmpty(name)) {
			permission = security.getPermissionInstance();
		} else {
			if (role != null) {
				PermissionSet pset = security.getPermissions(role);
				for (Permission p : pset)
					if (p.getName().equals(name)) {
						permission = p;
					}
			}
		}
		return permission;
	}
}
