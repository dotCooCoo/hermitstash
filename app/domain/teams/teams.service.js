/**
 * Teams Service — business logic for team CRUD and membership.
 * Wraps multi-step operations in transactions.
 */
var teamsRepo = require("../../data/repositories/teams.repo");
var filesRepo = require("../../data/repositories/files.repo");
var { transaction } = require("../../data/db/transaction");
var { ValidationError, NotFoundError, ForbiddenError } = require("../../shared/errors");

/**
 * Create a team. Creator becomes team admin.
 */
function createTeam(name, createdBy) {
  if (!name || !String(name).trim()) throw new ValidationError("Team name is required.");
  var trimmed = String(name).trim().slice(0, 100);

  var team = teamsRepo.createTeam({
    name: trimmed,
    createdBy: createdBy,
    createdAt: new Date().toISOString(),
  });
  teamsRepo.addMember({
    teamId: team._id,
    userId: createdBy,
    role: "admin",
    joinedAt: new Date().toISOString(),
  });
  return team;
}

/**
 * Delete a team and clean up all related data atomically.
 */
function deleteTeam(teamId, requestingUserId) {
  var team = teamsRepo.findTeamById(teamId);
  if (!team) throw new NotFoundError("Team not found.");

  // Verify requester is team admin or site admin
  var membership = teamsRepo.findMember(teamId, requestingUserId);
  if (!membership || membership.role !== "admin") {
    throw new ForbiddenError("Only team admins can delete teams.");
  }

  transaction(function () {
    // Remove all members
    teamsRepo.removeAllMembers(teamId);
    // Unassign files (don't delete them)
    var teamFiles = filesRepo.findAll({ teamId: teamId });
    for (var i = 0; i < teamFiles.length; i++) {
      filesRepo.update(teamFiles[i]._id, { $set: { teamId: null } });
    }
    // Remove team
    teamsRepo.removeTeam(teamId);
  });
}

/**
 * Add a member to a team.
 */
function addMember(teamId, userId, role) {
  var team = teamsRepo.findTeamById(teamId);
  if (!team) throw new NotFoundError("Team not found.");

  var existing = teamsRepo.findMember(teamId, userId);
  if (existing) throw new ValidationError("User is already a member.");

  teamsRepo.addMember({
    teamId: teamId,
    userId: userId,
    role: role || "member",
    joinedAt: new Date().toISOString(),
  });
}

/**
 * Remove a member from a team.
 */
function removeMember(teamId, userId) {
  var team = teamsRepo.findTeamById(teamId);
  if (!team) throw new NotFoundError("Team not found.");

  var member = teamsRepo.findMember(teamId, userId);
  if (!member) throw new NotFoundError("Member not found.");

  // Don't allow removing the last admin
  if (member.role === "admin") {
    var adminCount = teamsRepo.countAdmins(teamId);
    if (adminCount <= 1) throw new ValidationError("Cannot remove the last team admin.");
  }

  teamsRepo.removeMember(member._id);
}

module.exports = { createTeam, deleteTeam, addMember, removeMember };
