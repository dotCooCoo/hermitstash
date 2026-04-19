/**
 * Teams Repository — persistence logic for teams and team members.
 */
var { teams, teamMembers } = require("../../../lib/db");

// Teams
function findTeamById(id) { return teams.findOne({ _id: id }); }
function findAllTeams(query) { return teams.find(query || {}); }
function createTeam(doc) { return teams.insert(doc); }
function removeTeam(id) { return teams.remove({ _id: id }); }

// Members
function findMember(teamId, userId) { return teamMembers.findOne({ teamId: teamId, userId: userId }); }
function findMembers(teamId) { return teamMembers.find({ teamId: teamId }); }
function findUserTeams(userId) { return teamMembers.find({ userId: userId }); }
function addMember(doc) { return teamMembers.insert(doc); }
function removeMember(id) { return teamMembers.remove({ _id: id }); }
function removeAllMembers(teamId) {
  var members = teamMembers.find({ teamId: teamId });
  for (var i = 0; i < members.length; i++) teamMembers.remove({ _id: members[i]._id });
  return members.length;
}
// team_members.role is a sealed column — a SQL predicate on role compares plaintext against
// ciphertext and always returns zero. Load all members for the team and filter in JS.
function countAdmins(teamId) {
  return teamMembers.find({ teamId: teamId }).filter(function (m) { return m.role === "admin"; }).length;
}
function isMember(teamId, userId) { return !!teamMembers.findOne({ teamId: teamId, userId: userId }); }
function isTeamAdmin(teamId, userId) { var m = teamMembers.findOne({ teamId: teamId, userId: userId }); return m && m.role === "admin"; }

module.exports = {
  findTeamById, findAllTeams, createTeam, removeTeam,
  findMember, findMembers, findUserTeams, addMember, removeMember, removeAllMembers, countAdmins,
  isMember, isTeamAdmin,
};
