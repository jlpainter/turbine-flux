package org.apache.turbine.flux.modules.actions.user;

import java.util.List;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.fulcrum.security.entity.Group;
import org.apache.fulcrum.security.entity.Role;
import org.apache.fulcrum.security.model.turbine.TurbineAccessControlList;
import org.apache.fulcrum.security.torque.om.TurbineUser;
import org.apache.fulcrum.security.util.GroupSet;
import org.apache.fulcrum.security.util.RoleSet;
import org.apache.turbine.annotation.TurbineService;
import org.apache.turbine.flux.modules.actions.FluxAction;
import org.apache.turbine.fluxtest.om.TurbineUserGroupRole;
import org.apache.turbine.fluxtest.om.TurbineUserGroupRolePeer;
import org.apache.turbine.om.security.User;
import org.apache.turbine.pipeline.PipelineData;
import org.apache.turbine.services.security.SecurityService;
import org.apache.turbine.util.RunData;
import org.apache.velocity.context.Context;

/**
 * Change Password action.
 *
 */
public class FluxUserAction extends FluxAction {
	private static Log log = LogFactory.getLog(FluxUserAction.class);

	/** Injected service instance */
	@TurbineService
	private SecurityService security;

	/**
	 * ActionEvent responsible for inserting a new user into the Turbine security
	 * system.
	 */
	public void doInsert(PipelineData pipelineData, Context context) throws Exception {
		RunData data = getRunData(pipelineData);
		/*
		 * Create a TamboraUser object here, it will be used even if there is an error.
		 * It will be fed back into the context to give the user the chance to correct
		 * any errors.
		 */
		User user = security.getUserManager().getUserInstance();
		data.getParameters().setProperties(user);

		/*
		 * Grab the username entered in the form.
		 */
		String username = data.getParameters().getString("username");
		String password = data.getParameters().getString("password");

		if (password == null)
			password = "";

		/*
		 * Make sure this account doesn't already exist. If the account already exists
		 * then alert the user and make them change the username.
		 */
		if (security.accountExists(username)) {
			context.put("username", username);
			context.put("errorTemplate", "/screens/user/FluxUserAlreadyExists.vm");
			context.put("user", user);
			/*
			 * We are still in insert mode. So keep this value alive.
			 */
			data.getParameters().add("mode", "insert");
			setTemplate(data, "/user/FluxUserForm.vm");
		} else {
			/*
			 * Save the new user we just added
			 */
			security.addUser(user, password);
		}
	}

	/**
	 * ActionEvent responsible updating a user. Must check the input for integrity
	 * before allowing the user info to be update in the database.
	 */
	public void doUpdate(PipelineData pipelineData, Context context) throws Exception {
		RunData data = getRunData(pipelineData);
		String username = data.getParameters().getString("username");
		if (!StringUtils.isEmpty(username)) {
			if (security.accountExists(username)) {
				TurbineUser user = security.getUser(username);
				data.getParameters().setProperties(user);
				user.setModified(true);
				user.save();
			} else {
				log.error("User does not exist!");
			}
		}
	}

	/**
	 * ActionEvent responsible for removing a user from the Tambora system.
	 */
	public void doDelete(PipelineData pipelineData, Context context) throws Exception {

		try {
			RunData data = getRunData(pipelineData);
			String username = data.getParameters().getString("username");
			if (!StringUtils.isEmpty(username)) {
				if (security.accountExists(username)) {
					User user = security.getUser(username);
					security.removeUser(user);
				} else {
					log.error("User does not exist!");
				}
			}
		} catch (Exception e) {
			log.error("Could not remove user: " + e);
		}
	}

	/**
	 * Update the roles that are to assigned to a user for a project.
	 */
	public void doRoles(PipelineData pipelineData, Context context) throws Exception {
		RunData data = getRunData(pipelineData);
		/*
		 * Get the user we are trying to update. The username has been hidden in the
		 * form so we will grab the hidden username and use that to retrieve the user.
		 */
		String username = data.getParameters().getString("username");
		if (!StringUtils.isEmpty(username)) {
			if (security.accountExists(username)) {
				User user = security.getUser(username);

				// Get the Turbine ACL implementation
				TurbineAccessControlList acl = security.getUserManager().getACL(user);

				/*
				 * Grab all the Groups and Roles in the system.
				 */
				GroupSet groups = security.getAllGroups();
				RoleSet roles = security.getAllRoles();

				for (Group group : groups) {
					String groupName = group.getName();
					for (Role role : roles) {
						String roleName = role.getName();

						/*
						 * In the UserRoleForm.vm we made a checkbox for every possible Group/Role
						 * combination so we will compare every possible combination with the values
						 * that were checked off in the form. If we have a match then we will grant the
						 * user the role in the group.
						 */
						String groupRole = groupName + roleName;
						String formGroupRole = data.getParameters().getString(groupRole);

						if (formGroupRole != null && !acl.hasRole(role, group)) {
							// add the role for this user
							if (acl.hasRole(role) == false) {
								acl.getRoles().add(role);
								
								TurbineUserGroupRole tugr =  new TurbineUserGroupRole();
								tugr.setRoleId( (Integer) role.getId() );
								tugr.setGroupId( (Integer) group.getId() );
								tugr.setUserId( (Integer) user.getId() );
								tugr.setNew( false );
								//tugr.set
								List<TurbineUserGroupRole> tgrSaved = TurbineUserGroupRolePeer.doSelect( tugr );
								if (tgrSaved.isEmpty()) {
								    tugr.setNew( true );
								    TurbineUserGroupRolePeer.doInsert( tugr);
								}
								// contract problem
								//security.grant(user, group, role);
								
							}
						} else if (formGroupRole == null && acl.hasRole(role, group)) {
							// revoke the role for this user
							acl.getRoles().remove(role);
						}
					}
				}

			} else {
				log.error("User does not exist!");
			}
		}

	}

	/**
	 * Implement this to add information to the context.
	 */
	public void doPerform(PipelineData pipelineData, Context context) throws Exception {
		log.info("Running do perform!");
		getRunData(pipelineData).setMessage("Can't find the requested action!");
	}

}
