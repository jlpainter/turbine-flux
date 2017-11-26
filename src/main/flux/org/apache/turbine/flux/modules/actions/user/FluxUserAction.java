package org.apache.turbine.flux.modules.actions.user;

import java.util.List;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.fulcrum.security.entity.Group;
import org.apache.fulcrum.security.entity.Role;
import org.apache.fulcrum.security.model.turbine.TurbineAccessControlList;
import org.apache.fulcrum.security.torque.om.TurbineUser;
import org.apache.fulcrum.security.torque.om.TurbineUserPeer;
import org.apache.fulcrum.security.util.GroupSet;
import org.apache.fulcrum.security.util.RoleSet;
import org.apache.torque.criteria.Criteria;
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
		 * Grab the username entered in the form.
		 */
		String username = data.getParameters().getString("username");
		String password = data.getParameters().getString("password");

		if (!StringUtils.isEmpty(username) && !StringUtils.isEmpty(password)) {
			/*
			 * Make sure this account doesn't already exist. If the account already exists
			 * then alert the user and make them change the username.
			 */
			if (security.accountExists(username)) {
				context.put("username", username);
				context.put("errorTemplate", "/screens/user/FluxUserAlreadyExists.vm");

				data.getParameters().add("mode", "insert");
				setTemplate(data, "/user/FluxUserForm.vm");
			} else {

				try {
					/*
					 * Create a new user modeled directly from the SecurityServiceTest method
					 */

					// currently broken, gives wrong user instance type
					// User user = security.getUserInstance(username);
					// data.getParameters().setProperties(user);
					// security.addUser(user,password);

					// create the turbine user object directly
					TurbineUser tu = new TurbineUser();
					data.getParameters().setProperties(tu);

					// make sure username is set
					tu.setEntityName(username);

					// save
					tu.setNew(true);
					tu.save();

					// Use security to force the password
					security.forcePassword((User) tu, password);

				} catch (Exception e) {
					log.error("Error adding new user: " + e);
				}
			}

		} else {
			log.error("Cannot add user without username or password");
			data.getParameters().add("mode", "insert");
			setTemplate(data, "/user/FluxUserForm.vm");
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

				// get the new password from form submit
				String password = data.getParameters().getString("password");

				// Load the user
				Criteria criteria = new Criteria();
				criteria.where(TurbineUserPeer.LOGIN_NAME, username);
				TurbineUser user = TurbineUserPeer.doSelectSingleRecord(criteria);

				// this gives the wrong user type object
				// TurbineUser user = security.getUser(username);
				
				// This wrapped user does work for change password though... see below
				User tuwrap = security.getUser(username);

				if (user != null && tuwrap != null) {

					// get old password
					String oldpw = user.getPassword();

					// update all properties from form
					data.getParameters().setProperties(user);

					// save the changes to the user account
					user.setNew(false);
					user.setModified(true);
					user.save();

					// Only update if we received a new (non-empty) password
					if (!StringUtils.isEmpty(password)) {
						security.changePassword(tuwrap, oldpw, password);
					}

				}

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

					// revoke all permissions - currently broken
					// security.revokeAll(user);
					// security.removeUser(user);

					// get the user and revoke all permissions
					User user = security.getUser(username);
					revokeAll(user);

					// manually delete from the turbine user table entry
					Criteria criteria = new Criteria();
					criteria.where(TurbineUserPeer.LOGIN_NAME, username);
					TurbineUser tu = TurbineUserPeer.doSelectSingleRecord(criteria);
					TurbineUserPeer.doDelete(tu);

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

		try {
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
							boolean addGroupRole = false;

							// signal to add group
							if (!StringUtils.isEmpty(formGroupRole))
								addGroupRole = true;

							if (addGroupRole) {
								// only add if new
								if (!acl.hasRole(role, group)) {

									TurbineUserGroupRole tugr = new TurbineUserGroupRole();
									tugr.setRoleId((Integer) role.getId());
									tugr.setGroupId((Integer) group.getId());
									tugr.setUserId((Integer) user.getId());
									tugr.setNew(false);

									List<TurbineUserGroupRole> tgrSaved = TurbineUserGroupRolePeer.doSelect(tugr);
									if (tgrSaved.isEmpty()) {
										tugr.setNew(true);
										TurbineUserGroupRolePeer.doInsert(tugr);
									}

								}

							} else {

								// only remove if it was previously assigned
								if (acl.hasRole(role, group)) {

									// revoke the role for this user
									acl.getRoles(group).remove(role);

									// build the db obj and remove it
									TurbineUserGroupRole tugr = new TurbineUserGroupRole();
									tugr.setRoleId((Integer) role.getId());
									tugr.setGroupId((Integer) group.getId());
									tugr.setUserId((Integer) user.getId());
									tugr.setNew(false);

									TurbineUserGroupRole tgrSaved = TurbineUserGroupRolePeer.doSelectSingleRecord(tugr);
									if (tgrSaved != null)
										TurbineUserGroupRolePeer.doDelete(tgrSaved);

								}
							}

						}
					}

				} else {
					log.error("User does not exist!");
				}
			}

		} catch (Exception e) {
			log.error("Error on role assignment: " + e);
		}
	}

	/**
	 * Implement this to add information to the context.
	 */
	public void doPerform(PipelineData pipelineData, Context context) throws Exception {
		log.info("Running do perform!");
		getRunData(pipelineData).setMessage("Can't find the requested action!");
	}

	/**
	 * The security.revokeAll is currently not working
	 * 
	 * @param user
	 */
	private void revokeAll(User user) {
		try {
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

					// only remove if it was previously assigned
					if (acl.hasRole(role, group)) {

						// revoke the role for this user
						acl.getRoles(group).remove(role);

						// build the db obj and remove it
						TurbineUserGroupRole tugr = new TurbineUserGroupRole();
						tugr.setRoleId((Integer) role.getId());
						tugr.setGroupId((Integer) group.getId());
						tugr.setUserId((Integer) user.getId());
						tugr.setNew(false);

						TurbineUserGroupRole tgrSaved = TurbineUserGroupRolePeer.doSelectSingleRecord(tugr);
						if (tgrSaved != null)
							TurbineUserGroupRolePeer.doDelete(tgrSaved);

					}
				}

			}
		} catch (Exception e) {
			log.error("Error revoking role assignments for user: " + e);
		}

	}

}
