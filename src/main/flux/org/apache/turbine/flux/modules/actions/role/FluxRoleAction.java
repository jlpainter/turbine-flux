package org.apache.turbine.flux.modules.actions.role;

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
import org.apache.fulcrum.security.entity.Permission;
import org.apache.fulcrum.security.entity.Role;
import org.apache.fulcrum.security.torque.om.TurbinePermissionPeer;
import org.apache.fulcrum.security.torque.om.TurbineRolePermissionPeer;
import org.apache.fulcrum.security.util.EntityExistsException;
import org.apache.fulcrum.security.util.PermissionSet;
import org.apache.fulcrum.security.util.UnknownEntityException;
import org.apache.fulcrum.yaafi.framework.util.StringUtils;
import org.apache.torque.TorqueException;
import org.apache.torque.criteria.Criteria;
import org.apache.turbine.annotation.TurbineConfiguration;
import org.apache.turbine.annotation.TurbineService;
import org.apache.turbine.flux.modules.actions.FluxAction;
import org.apache.turbine.pipeline.PipelineData;
import org.apache.turbine.services.security.SecurityService;
import org.apache.turbine.util.RunData;
import org.apache.velocity.context.Context;

/**
 * Action to manager roles in Turbine.
 * 
 */
public class FluxRoleAction extends FluxAction {

	private static Log log = LogFactory.getLog(FluxRoleAction.class);

	/** Injected service instance */
	@TurbineService
	private SecurityService security;

	/** Injected configuration instance */
	@TurbineConfiguration
	private Configuration conf;

	public void doInsert(PipelineData pipelineData, Context context) throws Exception {
		RunData data = getRunData(pipelineData);
		Role role = security.getRoleInstance();
		data.getParameters().setProperties(role);

		String name = data.getParameters().getString("name");
		role.setName(name);

		try {
			security.addRole(role);
		} catch (EntityExistsException eee) {
			context.put("name", name);
			context.put("errorTemplate", "/screens/role/FluxRoleAlreadyExists.vm");
			context.put("role", role);
			/*
			 * We are still in insert mode. So keep this value alive.
			 */
			data.getParameters().add("mode", "insert");
			setTemplate(data, "/role/FluxRoleForm.vm");
		}

	}

	/**
	 * ActionEvent responsible updating a role. Must check the input for integrity
	 * before allowing the user info to be update in the database.
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
		Role role = security.getRoleByName(data.getParameters().getString("oldName"));
		String name = data.getParameters().getString("name");
		if (!StringUtils.isEmpty(name)) {
			try {
				security.renameRole(role, name);
			} catch (UnknownEntityException uee) {
				log.error("Could not rename role: " + uee);
				/*
				 * Should do something here but I still think we should use the an id so that
				 * this can't happen.
				 */
			}
		} else {
			log.error("Cannot update role to empty name");
		}

	}

	/**
	 * ActionEvent responsible for removing a role.
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

		try {

			Role role = security.getRoleByName(data.getParameters().getString("name"));
			
			// test that any linked permissions are also removed before removing the role
			PermissionSet pset = security.getPermissions(role);
			for (Permission p : pset)
				removePermission(role, p);

			// now remove the role
			security.removeRole(role);
		} catch (UnknownEntityException uee) {
			/*
			 * Should do something here but I still think we should use the an id so that
			 * this can't happen.
			 */
			log.error(uee);
		} catch (Exception e) {
			log.error("Could not remove role: " + e);
		}
	}

	/**
	 * Remove a role-permission link from the database
	 * 
	 * @param role
	 * @param permission
	 * @throws TorqueException
	 */
	private void removePermission(Role role, Permission permission) throws TorqueException {

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

	}

	/**
	 * Update the roles that are to assigned to a user for a project.
	 * 
	 * @param data
	 *            Turbine information.
	 * @param context
	 *            Context for web pages.
	 * @exception Exception
	 *                a generic exception.
	 */

	/**
	 * 
	 * This needs to be re-evaluated since the role/permission is not exposed by the
	 * role manager
	 * 
	 * This should pull from the TURBINE_ROLE_PERMISSION entries
	 *
	 **/

	//
	// public void doPermissions(PipelineData pipelineData, Context context) throws
	// Exception {
	// /*
	// * Grab the role we are trying to update.
	// */
	// Role role =
	// security.getRoleManager().getRoleByName(data.getParameters().getString("name"));
	//
	//
	// /*
	// * Grab the permissions for the role we are dealing with.
	// */
	// security.getPermissionManager().
	// PermissionSet rolePermissions = role.getPermissions();
	//
	// /*
	// * Grab all the permissions.
	// */
	// PermissionSet permissions =
	// security.getPermissionManager().getAllPermissions();
	//
	// String roleName = role.getName();
	//
	// for (int i = 0; i < permissions.length; i++) {
	// String permissionName = permissions[i].getName();
	// String rolePermission = roleName + permissionName;
	//
	// String formRolePermission = data.getParameters().getString(rolePermission);
	// Permission permission = TurbineSecurity.getPermissionByName(permissionName);
	//
	// if (formRolePermission != null && !rolePermissions.contains(permission)) {
	// /*
	// * Checkbox has been checked AND the role doesn't already contain this
	// * permission. So assign the permission to the role.
	// */
	//
	// System.out.println("adding " + permissionName + " to " + roleName);
	// role.grant(permission);
	// } else if (formRolePermission == null &&
	// rolePermissions.contains(permission)) {
	// /*
	// * Checkbox has not been checked AND the role contains this permission. So
	// * remove this permission from the role.
	// */
	// System.out.println("removing " + permissionName + " from " + roleName);
	// role.revoke(permission);
	// }
	// }
	// }

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
		log.info("Running do perform!");
		getRunData(pipelineData).setMessage("Can't find the requested action!");
	}
}
