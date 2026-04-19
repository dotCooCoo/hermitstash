var logger = require("../app/shared/logger");
var usersRepo = require("../app/data/repositories/users.repo");
var filesRepo = require("../app/data/repositories/files.repo");
var teamsRepo = require("../app/data/repositories/teams.repo");
var { parseJson } = require("../lib/multipart");
var requireAuth = require("../middleware/require-auth");
var audit = require("../lib/audit");
var teamsService = require("../app/domain/teams/teams.service");

module.exports = function (app) {
  // List user's teams
  app.get("/teams/api", (req, res) => {
    if (!requireAuth(req, res)) return;
    var memberships = teamsRepo.findUserTeams(req.user._id);
    var result = memberships.map(function (m) {
      var team = teamsRepo.findTeamById(m.teamId);
      if (!team) return null;
      return {
        _id: team._id,
        name: team.name,
        role: m.role,
        memberCount: teamsRepo.findMembers(team._id).length,
        createdAt: team.createdAt,
      };
    }).filter(Boolean);
    res.json({ teams: result });
  });

  // Create team
  app.post("/teams/create", async (req, res) => {
    if (!requireAuth(req, res)) return;
    try {
      var body = await parseJson(req);
      var team = teamsService.createTeam(body.name, req.user._id);
      audit.log(audit.ACTIONS.TEAM_CREATED, { targetId: team._id, details: "name: " + team.name, req: req });
      res.json({ success: true, teamId: team._id });
    } catch (e) {
      if (e.isAppError) return res.status(e.statusCode).json({ error: e.message });
      logger.error("Team create error", { error: e.message || String(e) });
      res.status(500).json({ error: "Failed to create team." });
    }
  });

  // Add member to team
  app.post("/teams/:teamId/members/add", async (req, res) => {
    if (!requireAuth(req, res)) return;
    if (!teamsRepo.isTeamAdmin(req.params.teamId, req.user._id) && req.user.role !== "admin") {
      return res.status(403).json({ error: "Only team admins can add members." });
    }
    try {
      var body = await parseJson(req);
      var userId = String(body.userId || "");
      if (!userId) return res.status(400).json({ error: "User ID required." });
      var target = usersRepo.findById(userId);
      if (!target) return res.status(404).json({ error: "User not found." });
      var role = body.role === "admin" ? "admin" : "member";
      teamsService.addMember(req.params.teamId, userId, role);
      audit.log(audit.ACTIONS.TEAM_MEMBER_ADDED, { targetId: req.params.teamId, details: "userId: " + userId, req: req });
      res.json({ success: true });
    } catch (e) {
      if (e.isAppError) return res.status(e.statusCode).json({ error: e.message });
      res.status(500).json({ error: "Failed to add member." });
    }
  });

  // Remove member from team
  app.post("/teams/:teamId/members/remove", async (req, res) => {
    if (!requireAuth(req, res)) return;
    if (!teamsRepo.isTeamAdmin(req.params.teamId, req.user._id) && req.user.role !== "admin") {
      return res.status(403).json({ error: "Only team admins can remove members." });
    }
    try {
      var body = await parseJson(req);
      var userId = String(body.userId || "");
      teamsService.removeMember(req.params.teamId, userId);
      audit.log(audit.ACTIONS.TEAM_MEMBER_REMOVED, { targetId: req.params.teamId, details: "userId: " + userId, req: req });
      res.json({ success: true });
    } catch (e) {
      if (e.isAppError) return res.status(e.statusCode).json({ error: e.message });
      res.status(500).json({ error: "Failed to remove member." });
    }
  });

  // List team members
  app.get("/teams/:teamId/members", (req, res) => {
    if (!requireAuth(req, res)) return;
    if (!teamsRepo.isMember(req.params.teamId, req.user._id) && req.user.role !== "admin") {
      return res.status(403).json({ error: "Not a member of this team." });
    }
    var members = teamsRepo.findMembers(req.params.teamId);
    var result = members.map(function (m) {
      var user = usersRepo.findById(m.userId);
      if (!user) return null;
      return { _id: m._id, userId: m.userId, email: user.email, displayName: user.displayName, role: m.role, joinedAt: m.joinedAt };
    }).filter(Boolean);
    res.json({ members: result });
  });

  // List team files
  app.get("/teams/:teamId/files", (req, res) => {
    if (!requireAuth(req, res)) return;
    if (!teamsRepo.isMember(req.params.teamId, req.user._id) && req.user.role !== "admin") {
      return res.status(403).json({ error: "Not a member of this team." });
    }
    var teamFiles = filesRepo.findAll({ teamId: req.params.teamId, status: "complete" });
    var result = teamFiles.map(function (f) {
      return {
        _id: f._id, shareId: f.shareId,
        originalName: f.originalName,
        size: f.size, downloads: f.downloads, createdAt: f.createdAt,
      };
    });
    res.json({ files: result });
  });

  // Delete team
  app.post("/teams/:teamId/delete", async (req, res) => {
    if (!requireAuth(req, res)) return;
    // Route-level auth: allow team admins or site admins
    if (!teamsRepo.isTeamAdmin(req.params.teamId, req.user._id) && req.user.role !== "admin") {
      return res.status(403).json({ error: "Only team admins can delete teams." });
    }
    try {
      teamsService.deleteTeam(req.params.teamId, req.user._id);
      audit.log(audit.ACTIONS.TEAM_DELETED, { targetId: req.params.teamId, req: req });
      res.json({ success: true });
    } catch (e) {
      // Site admins pass the route-level check but may not be team members;
      // the service enforces team-admin membership — suppress ForbiddenError for site admins
      if (e.isAppError && e.code === "FORBIDDEN" && req.user.role === "admin") {
        // Force-delete as site admin using the service's transactional path
        // by temporarily adding the admin as team admin, then retrying
        try {
          teamsService.addMember(req.params.teamId, req.user._id, "admin");
          teamsService.deleteTeam(req.params.teamId, req.user._id);
          audit.log(audit.ACTIONS.TEAM_DELETED, { targetId: req.params.teamId, req: req });
          return res.json({ success: true });
        } catch (e2) {
          if (e2.isAppError) return res.status(e2.statusCode).json({ error: e2.message });
          return res.status(500).json({ error: "Failed to delete team." });
        }
      }
      if (e.isAppError) return res.status(e.statusCode).json({ error: e.message });
      res.status(500).json({ error: "Failed to delete team." });
    }
  });
};
