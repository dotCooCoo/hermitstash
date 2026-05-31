"use strict";
/**
 * @module    b.calendar
 * @nav       Mail
 * @title     Calendar (JSCalendar)
 * @order     400
 * @slug      calendar
 *
 * @intro
 *   JSCalendar (RFC 8984) primitive. Wraps the framework's existing
 *   `b.safeIcal.parse` (RFC 5545 grammar + bounded parser) with the
 *   JSON-native JSCalendar surface JMAP Calendars (RFC 8984 / draft-
 *   ietf-jmap-calendars) requires for cross-protocol interop.
 *
 *   Scope:
 *     - `validate(jsCal)` — assert JSCalendar Event / Task / Note /
 *       Group shape (RFC 8984 §5 / §6 / §1.4.4).
 *     - `fromIcal(text, opts?)` — VCALENDAR.VEVENT → Event,
 *       VTODO → Task, VJOURNAL → Note. Mixed-component VCALENDARs
 *       return an array.
 *     - `toIcal(jsCal, opts?)` — Event → VEVENT, Task → VTODO, Note →
 *       VJOURNAL. Group emits a single VCALENDAR wrapping every
 *       entry's component.
 *     - `expandRecurrence(event, { from, to, max })` — RRULE expansion
 *       for FREQ=DAILY/WEEKLY/MONTHLY/YEARLY with UNTIL/COUNT/INTERVAL
 *       and BYDAY/BYMONTH/BYMONTHDAY/BYWEEKNO/BYYEARDAY/BYHOUR/
 *       BYMINUTE/BYSECOND/BYSETPOS. Multiple `recurrenceRules`
 *       expand independently and UNION per RFC 8984 §4.3.2.
 *
 *   Deferred-with-condition (no operator demand yet):
 *     - RFC 7529 non-Gregorian calendars.
 *     - Floating-timezone resolution against IANA TZDB.
 *
 * @card
 *   JSCalendar (RFC 8984) ↔ iCalendar (RFC 5545) bridge — validate,
 *   convert both directions, expand recurrences. Substrate for JMAP
 *   Calendars (RFC 8984 + draft-ietf-jmap-calendars).
 */

var safeIcal = require("./safe-ical");
var time     = require("./time");
var { defineClass } = require("./framework-error");

var CalendarError = defineClass("CalendarError", { alwaysPermanent: true });

// JSCalendar shape vocabulary — RFC 8984 §1.2 (`@type`) catalogues
// the discriminator strings every nested object MUST carry.
var JSCAL_TYPES = Object.freeze({
  Event:        "Event",
  Task:         "Task",
  // Note maps RFC 5545 §3.6.3 VJOURNAL — a dated, free-form journal
  // entry with no duration / progress / due semantics. Not formally
  // defined as an @type in RFC 8984 §1.2 (which only enumerates
  // Event + Task + Group); blamejs adopts `Note` as a recognised
  // extension shape for VJOURNAL round-trip interop with iCalendar
  // sources. Operators interoperating with strict RFC 8984 consumers
  // should map Note → Group or Note → custom-@type before exchange.
  Note:         "Note",
  Group:        "Group",
  Participant:  "Participant",
  Location:     "Location",
  Link:         "Link",
  Alert:        "Alert",
  Recurrence:   "RecurrenceRule",
  TimeZone:     "TimeZone",
});

// RFC 8984 §4.3.2 — frequencies recognised in `RecurrenceRule.frequency`.
var JSCAL_FREQUENCIES = Object.freeze({
  yearly: 1, monthly: 1, weekly: 1, daily: 1, hourly: 1, minutely: 1, secondly: 1,
});

// RFC 8984 §4.6.2 — alert action types.
var JSCAL_ALERT_ACTIONS = Object.freeze({
  display: 1, email: 1,
});

// RFC 8984 §6.4.3 — Task progress vocabulary. Mirrors RFC 5545 STATUS
// values for VTODO (`NEEDS-ACTION` / `IN-PROCESS` / `COMPLETED` /
// `CANCELLED`); JSCalendar lower-cases them. `failed` is NOT included
// — RFC 5545 STATUS does not define a `FAILED` value, so the iCal
// round-trip path could not safely emit it (strict consumers refuse
// the unknown STATUS token). Operators with a "failed" semantic
// model it via `progress: "cancelled"` + a vendor-namespaced
// extension property instead.
var JSCAL_TASK_PROGRESS = Object.freeze({
  "needs-action": 1, "in-process": 1, "completed": 1, "cancelled": 1,
});

// RFC 5545 §3.8.1.11 STATUS for VJOURNAL — Note carries DRAFT / FINAL
// / CANCELLED. JSCalendar lower-cases them on import/export. Note's
// `status` is OPTIONAL; absence on the wire maps to `status`
// unset (rather than defaulting to "draft" — operator intent is
// ambiguous when STATUS is omitted, per RFC 5545 grammar).
var JSCAL_NOTE_STATUS = Object.freeze({
  "draft": 1, "final": 1, "cancelled": 1,
});

// Recurrence-expansion caps. Mirror b.safeIcal's RRULE limits so the
// expand path can't outpace what the parser already permitted.
var MAX_EXPAND_INSTANCES = 4096;                                                                       // instance count cap, not bytes
var MAX_EXPAND_SPAN_MS   = 10 * 365 * 24 * 60 * 60 * 1000;                                             // allow:raw-time-literal — 10 year max expansion span

/**
 * @primitive b.calendar.validate
 * @signature b.calendar.validate(jsCal)
 * @since     0.11.31
 * @status    stable
 *
 * Validate a JSCalendar Event / Task / Note / Group object's
 * required-field shape per RFC 8984 §5 (Event) / §6 (Task) / §7 (Note) /
 * §1.4.4 (Group). Returns the input on success; throws
 * `CalendarError` on refusal with a `.code` naming the specific shape
 * rule that failed.
 *
 * @example
 *   b.calendar.validate({
 *     "@type":      "Event",
 *     uid:          "0e612e8b-1c4f-4e30-8e6a-4adc4e8b1c4f",
 *     updated:      "2026-05-21T10:00:00Z",
 *     title:        "Sprint planning",
 *     start:        "2026-05-22T09:00:00",
 *     duration:     "PT1H",
 *     timeZone:     "America/Los_Angeles",
 *   });
 */
function validate(jsCal) {
  if (!jsCal || typeof jsCal !== "object" || Array.isArray(jsCal)) {
    throw new CalendarError("calendar/bad-input",
      "b.calendar.validate: input must be a JSCalendar object");
  }
  var t = jsCal["@type"];
  if (t !== JSCAL_TYPES.Event && t !== JSCAL_TYPES.Task && t !== JSCAL_TYPES.Note && t !== JSCAL_TYPES.Group) {
    throw new CalendarError("calendar/bad-type",
      "b.calendar.validate: @type must be 'Event', 'Task', 'Note' or 'Group' (got " + JSON.stringify(t) + ")");
  }
  if (typeof jsCal.uid !== "string" || jsCal.uid.length === 0) {
    throw new CalendarError("calendar/no-uid",
      "b.calendar.validate: uid is required (RFC 8984 §5.1.4)");
  }
  if (jsCal.uid.length > 1024) {                                                                       // anti-DoS uid length cap
    throw new CalendarError("calendar/oversize-uid",
      "b.calendar.validate: uid exceeds 1024 bytes");
  }
  if (typeof jsCal.updated !== "string" || !_isUtcDateTime(jsCal.updated)) {
    throw new CalendarError("calendar/bad-updated",
      "b.calendar.validate: updated MUST be a UTCDateTime per RFC 8984 §1.4.3 (got " + JSON.stringify(jsCal.updated) + ")");
  }
  if (t === JSCAL_TYPES.Event) {
    if (jsCal.start !== undefined && (typeof jsCal.start !== "string" || !_isLocalDateTime(jsCal.start))) {
      throw new CalendarError("calendar/bad-start",
        "b.calendar.validate: Event.start MUST be a LocalDateTime");
    }
    if (jsCal.duration !== undefined && (typeof jsCal.duration !== "string" || !_isDuration(jsCal.duration))) {
      throw new CalendarError("calendar/bad-duration",
        "b.calendar.validate: Event.duration MUST be an RFC 8601 PnYnMnDTnHnMnS Duration");
    }
  }
  if (t === JSCAL_TYPES.Task) {
    if (jsCal.start !== undefined && (typeof jsCal.start !== "string" || !_isLocalDateTime(jsCal.start))) {
      throw new CalendarError("calendar/bad-start",
        "b.calendar.validate: Task.start MUST be a LocalDateTime (RFC 8984 §6.4)");
    }
    if (jsCal.due !== undefined && (typeof jsCal.due !== "string" || !_isLocalDateTime(jsCal.due))) {
      throw new CalendarError("calendar/bad-due",
        "b.calendar.validate: Task.due MUST be a LocalDateTime (RFC 8984 §6.4.4)");
    }
    if (jsCal.estimatedDuration !== undefined &&
        (typeof jsCal.estimatedDuration !== "string" || !_isDuration(jsCal.estimatedDuration))) {
      throw new CalendarError("calendar/bad-duration",
        "b.calendar.validate: Task.estimatedDuration MUST be an RFC 8601 PnYnMnDTnHnMnS Duration");
    }
    if (jsCal.progress !== undefined &&
        !Object.prototype.hasOwnProperty.call(JSCAL_TASK_PROGRESS, jsCal.progress)) {
      throw new CalendarError("calendar/bad-progress",
        "b.calendar.validate: Task.progress MUST be one of " +
        Object.keys(JSCAL_TASK_PROGRESS).join(" | ") + " (RFC 8984 §6.4.3)");
    }
    if (jsCal.percentComplete !== undefined) {
      // RFC 8984 §6.4.4 specifies `UnsignedInt` (integer). RFC 5545
      // §3.8.1.16 PERCENT-COMPLETE is also integer-typed. A float
      // would emit as `PERCENT-COMPLETE:12.5` which strict parsers
      // refuse.
      if (typeof jsCal.percentComplete !== "number" || !isFinite(jsCal.percentComplete) ||
          !Number.isInteger(jsCal.percentComplete) ||
          jsCal.percentComplete < 0 || jsCal.percentComplete > 100) {                                  // RFC 8984 §6 percent range
        throw new CalendarError("calendar/bad-percent",
          "b.calendar.validate: Task.percentComplete MUST be an integer in 0..100 (RFC 8984 §6.4.4 UnsignedInt)");
      }
    }
    if (jsCal.progressUpdated !== undefined &&
        (typeof jsCal.progressUpdated !== "string" || !_isUtcDateTime(jsCal.progressUpdated))) {
      throw new CalendarError("calendar/bad-progress-updated",
        "b.calendar.validate: Task.progressUpdated MUST be a UTCDateTime");
    }
  }
  if (t === JSCAL_TYPES.Note) {
    // Note (VJOURNAL) — dated free-form journal entry. RFC 5545
    // §3.6.3 permits an optional DTSTART (date or date-time) and
    // SUMMARY / DESCRIPTION; STATUS values are limited to DRAFT /
    // FINAL / CANCELLED. There is no DUE / DURATION / COMPLETED /
    // PERCENT-COMPLETE on VJOURNAL.
    if (jsCal.start !== undefined && (typeof jsCal.start !== "string" || !_isLocalDateTime(jsCal.start))) {
      throw new CalendarError("calendar/bad-start",
        "b.calendar.validate: Note.start MUST be a LocalDateTime (RFC 5545 §3.6.3)");
    }
    if (jsCal.duration !== undefined) {
      throw new CalendarError("calendar/bad-duration",
        "b.calendar.validate: Note.duration MUST NOT be set (RFC 5545 §3.6.3 VJOURNAL has no DURATION)");
    }
    if (jsCal.due !== undefined) {
      throw new CalendarError("calendar/bad-due",
        "b.calendar.validate: Note.due MUST NOT be set (DUE is a VTODO-only property)");
    }
    if (jsCal.progress !== undefined) {
      throw new CalendarError("calendar/bad-progress",
        "b.calendar.validate: Note.progress MUST NOT be set (progress is a Task-only property)");
    }
    if (jsCal.percentComplete !== undefined) {
      throw new CalendarError("calendar/bad-percent",
        "b.calendar.validate: Note.percentComplete MUST NOT be set (percentComplete is a Task-only property)");
    }
    if (jsCal.progressUpdated !== undefined) {
      throw new CalendarError("calendar/bad-progress-updated",
        "b.calendar.validate: Note.progressUpdated MUST NOT be set (progressUpdated is a Task-only property)");
    }
    if (jsCal.status !== undefined &&
        !Object.prototype.hasOwnProperty.call(JSCAL_NOTE_STATUS, jsCal.status)) {
      throw new CalendarError("calendar/bad-note-status",
        "b.calendar.validate: Note.status MUST be one of " +
        Object.keys(JSCAL_NOTE_STATUS).join(" | ") + " (RFC 5545 §3.8.1.11 VJOURNAL STATUS)");
    }
  }
  if (t === JSCAL_TYPES.Group) {
    // RFC 8984 §1.4.4 — a Group is a container envelope for multiple
    // Event / Task / Note entries that share a logical name +
    // categories. Group itself does not carry start / duration / due
    // / progress — those live on the entries. `entries` MUST be a
    // non-empty array; every entry MUST be a valid Event / Task /
    // Note (Groups nesting Groups is refused — the spec does not
    // define a nesting recursion semantic).
    if (!Array.isArray(jsCal.entries) || jsCal.entries.length === 0) {
      throw new CalendarError("calendar/bad-entries",
        "b.calendar.validate: Group.entries MUST be a non-empty array (RFC 8984 §1.4.4)");
    }
    for (var gei = 0; gei < jsCal.entries.length; gei += 1) {
      var entry = jsCal.entries[gei];
      if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
        throw new CalendarError("calendar/bad-entries",
          "b.calendar.validate: Group.entries[" + gei + "] MUST be an object");
      }
      var et = entry["@type"];
      if (et !== JSCAL_TYPES.Event && et !== JSCAL_TYPES.Task && et !== JSCAL_TYPES.Note) {
        throw new CalendarError("calendar/bad-entries",
          "b.calendar.validate: Group.entries[" + gei + "].@type MUST be 'Event', 'Task' or 'Note' " +
          "(got " + JSON.stringify(et) + ") — Groups do not nest");
      }
      // Recurse into each entry so per-type shape rules apply.
      validate(entry);
    }
    if (jsCal.source !== undefined && typeof jsCal.source !== "string") {
      throw new CalendarError("calendar/bad-source",
        "b.calendar.validate: Group.source MUST be a string URI when present (RFC 8984 §1.4.4)");
    }
    if (jsCal.categories !== undefined) {
      // `typeof null === "object"` would let `categories:
      // null` through this check, and the subsequent Object.keys
      // throws a raw TypeError instead of a structured CalendarError.
      // Refuse null explicitly so callers depending on the
      // `calendar/bad-categories` refusal code stay stable.
      if (jsCal.categories === null || typeof jsCal.categories !== "object" ||
          Array.isArray(jsCal.categories)) {
        throw new CalendarError("calendar/bad-categories",
          "b.calendar.validate: Group.categories MUST be a String-keyed Boolean object (RFC 8984 §1.4.4)");
      }
      var catKeys = Object.keys(jsCal.categories);
      for (var ci = 0; ci < catKeys.length; ci += 1) {
        if (jsCal.categories[catKeys[ci]] !== true) {
          throw new CalendarError("calendar/bad-categories",
            "b.calendar.validate: Group.categories['" + catKeys[ci] + "'] MUST be `true` (boolean set per RFC 8984 §1.4.4)");
        }
      }
    }
    // Group itself MUST NOT carry the entry-specific fields. Refuse
    // explicit setting so operators don't accidentally model entry
    // state on the envelope.
    if (jsCal.start !== undefined || jsCal.duration !== undefined || jsCal.due !== undefined ||
        jsCal.progress !== undefined || jsCal.percentComplete !== undefined ||
        jsCal.progressUpdated !== undefined || jsCal.recurrenceRules !== undefined) {
      throw new CalendarError("calendar/bad-group",
        "b.calendar.validate: Group MUST NOT carry start / duration / due / progress / " +
        "percentComplete / progressUpdated / recurrenceRules — those live on the entries");
    }
  }
  if (t !== JSCAL_TYPES.Group && jsCal.recurrenceRules !== undefined) {
    if (!Array.isArray(jsCal.recurrenceRules)) {
      throw new CalendarError("calendar/bad-recurrence",
        "b.calendar.validate: recurrenceRules MUST be an array of RecurrenceRule");
    }
    for (var ri = 0; ri < jsCal.recurrenceRules.length; ri += 1) {
      var rr = jsCal.recurrenceRules[ri];
      if (!rr || typeof rr !== "object" || rr["@type"] !== "RecurrenceRule") {
        throw new CalendarError("calendar/bad-recurrence",
          "b.calendar.validate: recurrenceRules[" + ri + "].@type MUST be 'RecurrenceRule'");
      }
      if (!Object.prototype.hasOwnProperty.call(JSCAL_FREQUENCIES, rr.frequency)) {
        throw new CalendarError("calendar/bad-recurrence",
          "b.calendar.validate: recurrenceRules[" + ri + "].frequency MUST be one of " +
          Object.keys(JSCAL_FREQUENCIES).join(" | "));
      }
    }
  }
  if (jsCal.alerts !== undefined) {
    if (jsCal.alerts === null || typeof jsCal.alerts !== "object" || Array.isArray(jsCal.alerts)) {
      throw new CalendarError("calendar/bad-alerts",
        "b.calendar.validate: alerts MUST be an object map keyed by alert-id");
    }
    var alertKeys = Object.keys(jsCal.alerts);
    for (var ai = 0; ai < alertKeys.length; ai += 1) {
      var alert = jsCal.alerts[alertKeys[ai]];
      if (!alert || alert["@type"] !== "Alert") {
        throw new CalendarError("calendar/bad-alerts",
          "b.calendar.validate: alerts[" + alertKeys[ai] + "].@type MUST be 'Alert'");
      }
      if (alert.action && !Object.prototype.hasOwnProperty.call(JSCAL_ALERT_ACTIONS, alert.action)) {
        throw new CalendarError("calendar/bad-alerts",
          "b.calendar.validate: alerts[" + alertKeys[ai] + "].action MUST be one of " +
          Object.keys(JSCAL_ALERT_ACTIONS).join(" | "));
      }
    }
  }
  return jsCal;
}

/**
 * @primitive b.calendar.fromIcal
 * @signature b.calendar.fromIcal(text, opts?)
 * @since     0.11.31
 * @status    stable
 *
 * Parse iCalendar text (RFC 5545) via `b.safeIcal.parse` and map each
 * VEVENT → JSCalendar Event, VTODO → Task, and VJOURNAL → Note
 * (RFC 8984 §5 / §6 / §7). Returns a single object when the VCALENDAR
 * holds exactly one component, or an array across all components when
 * there are several.
 *
 * @opts
 *   safeIcalOpts: object,   // forwarded to b.safeIcal.parse (caps, allowExperimental, etc.)
 *
 * @example
 *   b.calendar.fromIcal(
 *     "BEGIN:VCALENDAR\\r\\nVERSION:2.0\\r\\n" +
 *     "BEGIN:VEVENT\\r\\nUID:a@b\\r\\nDTSTAMP:20260521T100000Z\\r\\n" +
 *     "DTSTART:20260522T090000Z\\r\\nDURATION:PT1H\\r\\n" +
 *     "SUMMARY:Sprint\\r\\nEND:VEVENT\\r\\nEND:VCALENDAR\\r\\n");
 *   // → { "@type":"Event", uid:"a@b", updated:"2026-05-21T10:00:00Z", ... }
 */
function fromIcal(text, opts) {
  // Forward parser options to b.safeIcal.parse. Accept BOTH the
  // documented nested form (`{ safeIcalOpts: { profile, caps, ... } }`)
  // AND the historically-working top-level form (`{ profile: "balanced" }`)
  // so neither caller regresses; the nested form wins on conflict. The
  // `safeIcalOpts` wrapper key itself is stripped before forwarding.
  var icalOpts = Object.assign({}, opts || {}, (opts && opts.safeIcalOpts) || {});
  delete icalOpts.safeIcalOpts;
  var ast = safeIcal.parse(text, icalOpts);
  var events   = (ast && ast.vcalendar && ast.vcalendar.vevent)   || [];
  var todos    = (ast && ast.vcalendar && ast.vcalendar.vtodo)    || [];
  var journals = (ast && ast.vcalendar && ast.vcalendar.vjournal) || [];
  if (events.length === 0 && todos.length === 0 && journals.length === 0) {
    throw new CalendarError("calendar/no-component",
      "b.calendar.fromIcal: VCALENDAR has no VEVENT, VTODO or VJOURNAL components");
  }
  var converted = events.map(_veventToJsCalEvent)
    .concat(todos.map(_vtodoToJsCalTask))
    .concat(journals.map(_vjournalToJsCalNote));
  return converted.length === 1 ? converted[0] : converted;
}

/**
 * @primitive b.calendar.toIcal
 * @signature b.calendar.toIcal(jsCal, opts?)
 * @since     0.11.31
 * @status    stable
 *
 * Render a JSCalendar object back to RFC 5545 iCalendar text — Event →
 * VEVENT, Task → VTODO, Note → VJOURNAL, and a Group to a VCALENDAR
 * carrying each member component. Returns a CRLF-terminated string
 * wrapped in a `BEGIN:VCALENDAR / VERSION:2.0 /
 * PRODID:-//blamejs//Calendar//EN / … / END:VCALENDAR` envelope per
 * RFC 5545 §3.4.
 *
 * @opts
 *   prodid: string,   // PRODID value to emit; default "-//blamejs//Calendar//EN"
 *
 * @example
 *   b.calendar.toIcal({
 *     "@type":  "Event",
 *     uid:      "a@b",
 *     updated:  "2026-05-21T10:00:00Z",
 *     title:    "Sprint",
 *     start:    "2026-05-22T09:00:00",
 *     duration: "PT1H",
 *   });
 */
function toIcal(jsCal, opts) {
  validate(jsCal);
  var prodid = (opts && opts.prodid) || "-//blamejs//Calendar//EN";
  // RFC 8984 §1.4.4 — a Group emits a single VCALENDAR envelope
  // containing every entry's component in declared order. The Group's
  // own uid + updated + name + description are NOT round-tripped to
  // iCalendar (RFC 5545 has no envelope-level metadata for these);
  // operators preserving Group metadata across a round-trip use the
  // JSON-native JSCalendar surface.
  if (jsCal["@type"] === "Group") {
    var groupLines = [
      "BEGIN:VCALENDAR",
      "VERSION:2.0",
      "PRODID:" + prodid,
    ];
    for (var gei2 = 0; gei2 < jsCal.entries.length; gei2 += 1) {
      var entryIcal = toIcal(jsCal.entries[gei2], { prodid: prodid });
      // Strip outer VCALENDAR envelope; keep inner component lines.
      var entryLines = entryIcal.split("\r\n");
      for (var eli = 0; eli < entryLines.length; eli += 1) {
        var line = entryLines[eli];
        if (line && line !== "BEGIN:VCALENDAR" && line !== "VERSION:2.0" &&
            line.indexOf("PRODID:") !== 0 && line !== "END:VCALENDAR") {
          groupLines.push(line);
        }
      }
    }
    groupLines.push("END:VCALENDAR");
    return groupLines.join("\r\n") + "\r\n";
  }
  // RFC 8984 §6 — JSCalendar Task maps to RFC 5545 §3.6.2 VTODO; Event
  // maps to VEVENT. The wrapper + most properties are identical; the
  // wrapping component tag + Task-specific fields (DUE / STATUS /
  // PERCENT-COMPLETE / COMPLETED) diverge.
  var component = jsCal["@type"] === "Task"
    ? "VTODO"
    : jsCal["@type"] === "Note" ? "VJOURNAL" : "VEVENT";
  var lines = [
    "BEGIN:VCALENDAR",
    "VERSION:2.0",
    "PRODID:" + prodid,
    "BEGIN:" + component,
    "UID:" + _foldLine(jsCal.uid),
    "DTSTAMP:" + _utcDateTimeToIcal(jsCal.updated),
  ];
  if (jsCal.title) lines.push("SUMMARY:" + _foldLine(_escapeText(jsCal.title)));
  if (jsCal.description) lines.push("DESCRIPTION:" + _foldLine(_escapeText(jsCal.description)));
  if (jsCal.start) {
    // RFC 8984 §1.4.4 maps `timeZone: "Etc/UTC"` to a `Z`-suffix
    // DTSTART (RFC 5545 §3.3.5 form 2); any other named timezone
    // maps to a TZID parameter (form 3); no timeZone leaves DTSTART
    // as floating local time (form 1).
    var dtStartIcal = _localDateTimeToIcal(jsCal.start);
    if (jsCal.timeZone === "Etc/UTC" || jsCal.timeZone === "UTC") {
      lines.push("DTSTART:" + dtStartIcal + "Z");
    } else if (jsCal.timeZone) {
      lines.push("DTSTART;TZID=" + jsCal.timeZone + ":" + dtStartIcal);
    } else {
      lines.push("DTSTART:" + dtStartIcal);
    }
  }
  // RFC 5545 §3.8.2.3 — DUE is Task-only; same TZID/UTC handling as DTSTART.
  if (component === "VTODO" && jsCal.due) {
    var dueIcal = _localDateTimeToIcal(jsCal.due);
    if (jsCal.timeZone === "Etc/UTC" || jsCal.timeZone === "UTC") {
      lines.push("DUE:" + dueIcal + "Z");
    } else if (jsCal.timeZone) {
      lines.push("DUE;TZID=" + jsCal.timeZone + ":" + dueIcal);
    } else {
      lines.push("DUE:" + dueIcal);
    }
  }
  // RFC 8984 §6 — Task carries `estimatedDuration` (RFC 5545 DURATION).
  // Event uses `duration`. Both map to the same iCalendar property.
  var icalDuration = component === "VTODO"
    ? (jsCal.estimatedDuration || jsCal.duration)
    : jsCal.duration;
  if (icalDuration) lines.push("DURATION:" + icalDuration);
  // RFC 5545 §3.8.1.11 STATUS — Task progress maps directly; the four
  // RFC 8984 §6.4.3 progress values (`needs-action` / `in-process` /
  // `completed` / `cancelled`) are the same wire strings.
  if (component === "VTODO" && jsCal.progress) {
    lines.push("STATUS:" + String(jsCal.progress).toUpperCase());
  }
  // RFC 5545 §3.8.1.11 — VJOURNAL STATUS values are DRAFT / FINAL /
  // CANCELLED. JSCalendar Note carries them lower-cased; emit upper.
  if (component === "VJOURNAL" && jsCal.status) {
    lines.push("STATUS:" + String(jsCal.status).toUpperCase());
  }
  if (component === "VTODO" && typeof jsCal.percentComplete === "number") {
    lines.push("PERCENT-COMPLETE:" + jsCal.percentComplete);
  }
  if (component === "VTODO" && jsCal.progressUpdated) {
    lines.push("COMPLETED:" + _utcDateTimeToIcal(jsCal.progressUpdated));
  }
  if (Array.isArray(jsCal.locations) || (jsCal.locations && typeof jsCal.locations === "object")) {
    var locValues = Array.isArray(jsCal.locations) ? jsCal.locations : Object.values(jsCal.locations);
    for (var li = 0; li < locValues.length; li += 1) {
      var loc = locValues[li];
      if (loc && typeof loc.name === "string") {
        lines.push("LOCATION:" + _foldLine(_escapeText(loc.name)));
      }
    }
  }
  if (Array.isArray(jsCal.recurrenceRules)) {
    for (var rri = 0; rri < jsCal.recurrenceRules.length; rri += 1) {
      lines.push("RRULE:" + _recurrenceRuleToIcal(jsCal.recurrenceRules[rri]));
    }
  }
  lines.push("END:" + component, "END:VCALENDAR");
  return lines.join("\r\n") + "\r\n";
}

/**
 * @primitive b.calendar.expandRecurrence
 * @signature b.calendar.expandRecurrence(event, opts)
 * @since     0.11.31
 * @status    stable
 *
 * Expand a JSCalendar Event's `recurrenceRules` into concrete start
 * timestamps in the operator's `[from, to]` window. Returns an array
 * of ISO 8601 UTC strings (`yyyy-mm-ddTHH:MM:SSZ`). Bounded by
 * `MAX_EXPAND_INSTANCES` (4096) + `MAX_EXPAND_SPAN_MS` (10 years) to
 * defend against the RRULE recurrence-bomb expansion class.
 *
 * v1 supports FREQ=DAILY/WEEKLY/MONTHLY/YEARLY with INTERVAL, COUNT,
 * UNTIL. BYDAY / BYMONTH / BYMONTHDAY / BYWEEKNO / BYYEARDAY /
 * BYHOUR / BYMINUTE / BYSECOND refine the base frequency. BYSETPOS
 * picks the Nth candidate from the BY*-filtered set within a FREQ
 * interval (positive = 1-indexed from start, negative = from end);
 * supported for FREQ=MONTHLY / YEARLY / WEEKLY with day-granularity
 * candidates (time-of-day inherited from start). Multiple
 * `recurrenceRules` are expanded independently and UNIONed; per
 * RFC 8984 §4.3.2 each rule's `count` cap applies per-rule, not to
 * the combined set. (RFC 7529 non-Gregorian calendars not in scope.)
 *
 * @opts
 *   from: string,    // ISO 8601 UTC timestamp — lower bound of expansion window
 *   to:   string,    // ISO 8601 UTC timestamp — upper bound (window <= 10 years)
 *   max:  number,    // instance-count cap (default 4096; never exceeds MAX_EXPAND_INSTANCES)
 *
 * @example
 *   b.calendar.expandRecurrence(
 *     { "@type": "Event", uid: "x", updated: "2026-05-21T10:00:00Z",
 *       start: "2026-05-22T09:00:00",
 *       recurrenceRules: [{ "@type": "RecurrenceRule", frequency: "daily", count: 5 }] },
 *     { from: "2026-05-22T00:00:00Z", to: "2026-06-01T00:00:00Z" });
 *   // → ["2026-05-22T09:00:00Z", "2026-05-23T09:00:00Z", ..., "2026-05-26T09:00:00Z"]
 */
function expandRecurrence(event, opts) {
  validate(event);
  opts = opts || {};
  if (!Array.isArray(event.recurrenceRules) || event.recurrenceRules.length === 0) {
    return event.start ? [_localToUtc(event.start)] : [];
  }
  var fromMs = opts.from ? Date.parse(opts.from) : null;
  var toMs   = opts.to   ? Date.parse(opts.to)   : null;
  if (fromMs !== null && toMs !== null) {
    if (toMs - fromMs > MAX_EXPAND_SPAN_MS) {
      throw new CalendarError("calendar/oversize-expansion-span",
        "b.calendar.expandRecurrence: window [" + opts.from + ", " + opts.to + "] exceeds 10 years");
    }
    if (toMs < fromMs) {
      throw new CalendarError("calendar/bad-expansion-window",
        "b.calendar.expandRecurrence: opts.to must be after opts.from");
    }
  }
  var maxCount = Math.min(opts.max || MAX_EXPAND_INSTANCES, MAX_EXPAND_INSTANCES);
  // JSCalendar's LocalDateTime is FLOATING when no timeZone is set;
  // for expansion we treat it as already-UTC so the returned ISO
  // strings carry the same wall-clock the operator stored. Appending
  // `Z` to the LocalDateTime sidesteps Date.parse's host-locale
  // interpretation (which would otherwise mangle the wall-clock).
  var startInput = _isLocalDateTime(event.start) ? event.start + "Z" : event.start;
  var startMs = Date.parse(startInput);
  if (!isFinite(startMs)) {
    throw new CalendarError("calendar/bad-start",
      "b.calendar.expandRecurrence: event.start is not a parseable date");
  }
  // RFC 8984 §4.3.2 — when multiple RecurrenceRule objects are
  // specified, they are expanded independently and the resulting
  // instances are UNIONed (deduped + sorted ascending). Per-rule
  // count caps apply per-rule per the same section.
  var globalStepBudget = MAX_EXPAND_INSTANCES * 366;                                                   // total days/year step budget shared across all rules
  var seen = Object.create(null);
  var unioned = [];
  for (var rrIndex = 0; rrIndex < event.recurrenceRules.length; rrIndex += 1) {
    var perRule = _expandSingleRule(event.recurrenceRules[rrIndex], startMs, {
      fromMs:        fromMs,
      toMs:          toMs,
      maxCount:      maxCount,
      stepBudgetRef: { remaining: globalStepBudget },
    });
    globalStepBudget = perRule.stepBudgetRemaining;
    for (var pi = 0; pi < perRule.instances.length; pi += 1) {
      var iso = perRule.instances[pi];
      if (!seen[iso]) {
        seen[iso] = true;
        unioned.push(iso);
      }
    }
  }
  unioned.sort();
  return unioned.length > maxCount ? unioned.slice(0, maxCount) : unioned;
}

// Expand ONE RecurrenceRule per the v0.11.31..v0.11.36 logic. Returns
// `{ instances: [isoZ...], stepBudgetRemaining: <int> }`. Caller is
// responsible for merging across rules (deduplication + sort + global
// cap).
function _expandSingleRule(rule, startMs, ctx) {
  var fromMs   = ctx.fromMs;
  var toMs     = ctx.toMs;
  var maxCount = ctx.maxCount;
  var out = [];
  var interval = Math.max(1, parseInt(rule.interval || 1, 10));
  var freq = rule.frequency;
  var count = isFinite(rule.count) ? rule.count : Infinity;
  var untilMs = rule.until ? Date.parse(rule.until) : Infinity;
  // RFC 5545 §3.3.10 BY* filters narrow which stepped occurrences
  // emit. We support the BYDAY/BYMONTH/BYMONTHDAY subset; rule
  // instances that fail the filter are stepped past WITHOUT counting
  // against `count` (per RFC 5545 BY* expansion semantics — only
  // surviving instances count).
  var byDaySet = null;
  if (Array.isArray(rule.byDay) && rule.byDay.length > 0) {
    byDaySet = Object.create(null);
    var dayCodes = { su: 0, mo: 1, tu: 2, we: 3, th: 4, fr: 5, sa: 6 };
    for (var bi = 0; bi < rule.byDay.length; bi += 1) {
      var entry = rule.byDay[bi];
      var dayKey = (entry && entry.day ? entry.day : entry || "").toLowerCase();
      if (Object.prototype.hasOwnProperty.call(dayCodes, dayKey)) {
        byDaySet[dayCodes[dayKey]] = true;
      }
    }
  }
  var byMonthSet = null;
  if (Array.isArray(rule.byMonth) && rule.byMonth.length > 0) {
    byMonthSet = Object.create(null);
    for (var mi = 0; mi < rule.byMonth.length; mi += 1) {
      var mn = parseInt(rule.byMonth[mi], 10);
      if (isFinite(mn) && mn >= 1 && mn <= 12) byMonthSet[mn] = true;                                  // 12 calendar months
    }
  }
  var byMonthDaySet = null;
  if (Array.isArray(rule.byMonthDay) && rule.byMonthDay.length > 0) {
    byMonthDaySet = Object.create(null);
    for (var mdi = 0; mdi < rule.byMonthDay.length; mdi += 1) {
      var mdn = parseInt(rule.byMonthDay[mdi], 10);
      if (isFinite(mdn) && mdn !== 0 && mdn >= -31 && mdn <= 31) byMonthDaySet[mdn] = true;            // calendar day-of-month bounds
    }
  }
  // RFC 5545 §3.3.10 — BYWEEKNO refines yearly recurrences to specific
  // ISO 8601 week numbers (1..53 or -1..-53). Implementation
  // computes the ISO week of each candidate instance + compares.
  var byWeekNoSet = null;
  if (Array.isArray(rule.byWeekNo) && rule.byWeekNo.length > 0) {
    byWeekNoSet = Object.create(null);
    for (var wni = 0; wni < rule.byWeekNo.length; wni += 1) {
      var wn = parseInt(rule.byWeekNo[wni], 10);
      if (isFinite(wn) && wn !== 0 && wn >= -53 && wn <= 53) byWeekNoSet[wn] = true;                   // ISO 8601 week-number bounds
    }
  }
  // BYYEARDAY — day-of-year (1..366 or -1..-366; negative counts from
  // the end of the year per RFC 5545 §3.3.10).
  var byYearDaySet = null;
  if (Array.isArray(rule.byYearDay) && rule.byYearDay.length > 0) {
    byYearDaySet = Object.create(null);
    for (var ydi = 0; ydi < rule.byYearDay.length; ydi += 1) {
      var yd = parseInt(rule.byYearDay[ydi], 10);
      if (isFinite(yd) && yd !== 0 && yd >= -366 && yd <= 366) byYearDaySet[yd] = true;                // day-of-year bounds
    }
  }
  // BYHOUR / BYMINUTE / BYSECOND — time-of-day filters. RFC 5545 §3.3.10
  // bounds: hours 0..23, minutes 0..59, seconds 0..60 (60 covers
  // POSIX leap-second representation).
  function _bySet(arr, lo, hi) {
    if (!Array.isArray(arr) || arr.length === 0) return null;
    var s = Object.create(null);
    var hasAny = false;
    for (var i = 0; i < arr.length; i += 1) {
      var n = parseInt(arr[i], 10);
      if (isFinite(n) && n >= lo && n <= hi) { s[n] = true; hasAny = true; }
    }
    // When every value in the BY* list is out of range,
    // return null instead of an empty set. An empty truthy set would
    // cause `_matchesBy` to reject every candidate (`!set[n]` is
    // true) and silently turn malformed input into a "match nothing"
    // rule. Returning null lets the rule fall through to the next
    // unfiltered candidate per RFC 5545's tolerant grammar.
    return hasAny ? s : null;
  }
  var byHourSet   = _bySet(rule.byHour,   0, 23);                                                      // RFC 5545 hour range
  var byMinuteSet = _bySet(rule.byMinute, 0, 59);                                                      // RFC 5545 minute range
  var bySecondSet = _bySet(rule.bySecond, 0, 60);                                                      // allow:raw-time-literal — second-of-minute upper bound (0..60); coincidental multiple-of-60, not a duration, C.TIME N/A

  function _isoWeekParts(d) {
    // ISO 8601 week-of-year + week-year. The week-YEAR can differ
    // from the Gregorian year for early-Jan / late-Dec boundary
    // dates (e.g. 2021-01-01 is ISO week 53 of WEEK-YEAR 2020).
    // Returns { week, year }.
    var tmp = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()));
    var dayOfWeek = tmp.getUTCDay() || 7;
    tmp.setUTCDate(tmp.getUTCDate() + 4 - dayOfWeek);                                                  // ISO week-year anchor (Thursday)
    var weekYear = tmp.getUTCFullYear();
    var yearStart = new Date(Date.UTC(weekYear, 0, 1));
    var week = Math.ceil((((tmp - yearStart) / 86400000) + 1) / 7);
    return { week: week, year: weekYear };
  }
  function _isoWeekOf(d) {
    return _isoWeekParts(d).week;
  }
  function _yearDayOf(d) {
    var startOfYear = new Date(Date.UTC(d.getUTCFullYear(), 0, 1));
    return Math.floor((d - startOfYear) / 86400000) + 1;                                               // allow:raw-time-literal — 86400000 ms/day
  }
  function _daysInYear(year) {
    return ((year % 4 === 0 && year % 100 !== 0) || year % 400 === 0) ? 366 : 365;                      // Gregorian leap-year rule
  }
  function _matchesBy(t) {
    var d = new Date(t);
    if (byDaySet && !byDaySet[d.getUTCDay()]) return false;
    if (byMonthSet && !byMonthSet[d.getUTCMonth() + 1]) return false;
    if (byMonthDaySet && !byMonthDaySet[d.getUTCDate()]) return false;
    if (byWeekNoSet) {
      // ISO week-year vs Gregorian year. 2021-01-01 is ISO
      // week 53 of WEEK-YEAR 2020 (since 2021 only has 52 ISO weeks).
      // Comparing only the numeric week would let a Jan 1 2021 date
      // match a BYWEEKNO=53 rule whose implicit year is 2021. Refuse
      // when the candidate's ISO week-year doesn't match the
      // candidate's Gregorian year (the most common operator-intent
      // alignment); operators with boundary-crossing rules opt in via
      // a future explicit knob if demand surfaces.
      var iso = _isoWeekParts(d);
      if (iso.year !== d.getUTCFullYear()) return false;
      var lastWeek = _isoWeekOf(new Date(Date.UTC(d.getUTCFullYear(), 11, 28)));                       // Dec 28 always in last ISO week
      if (!byWeekNoSet[iso.week] && !byWeekNoSet[-(lastWeek - iso.week + 1)]) return false;
    }
    if (byYearDaySet) {
      var yd = _yearDayOf(d);
      var dayCount = _daysInYear(d.getUTCFullYear());
      if (!byYearDaySet[yd] && !byYearDaySet[-(dayCount - yd + 1)]) return false;
    }
    if (byHourSet   && !byHourSet[d.getUTCHours()])     return false;
    if (byMinuteSet && !byMinuteSet[d.getUTCMinutes()]) return false;
    if (bySecondSet && !bySecondSet[d.getUTCSeconds()]) return false;
    return true;
  }
  // RFC 5545 §3.3.10 BYSETPOS — picks the Nth candidate from the
  // BY*-filtered set within a FREQ interval. Positive = 1-indexed
  // from start; negative = from end. Operators reach for this most
  // often with "last Friday of month" (FREQ=MONTHLY;BYDAY=FR;
  // BYSETPOS=-1) or "second Tuesday of month" (BYSETPOS=2).
  //
  // v1 supports BYSETPOS for FREQ=MONTHLY / YEARLY / WEEKLY at
  // day-granularity — candidates are days within the period at the
  // start's time-of-day. Sub-day BY* filters (byHour/byMinute/
  // bySecond) are ignored under BYSETPOS for v1; the rare combo
  // (BYSETPOS + byHour) reverts to the standard non-bysetpos step
  // path when applicable.
  var bySetPosArr = _bySetPosArray(rule.bySetPos);
  if (bySetPosArr) {
    return _expandWithBysetpos({
      rule:         rule,
      startMs:      startMs,
      freq:         freq,
      interval:     interval,
      count:        count,
      untilMs:      untilMs,
      fromMs:       fromMs,
      toMs:         toMs,
      maxCount:     maxCount,
      matchesBy:    _matchesBy,
      bySetPos:     bySetPosArr,
      stepBudgetRef: ctx.stepBudgetRef,
    });
  }

  var t = startMs;
  // Safety cap on the step loop: at most MAX_EXPAND_INSTANCES * 366
  // iterations so BY* filters that match sparsely (e.g. FREQ=DAILY;
  // BYMONTH=1 — only Jan days survive) cannot loop forever inside
  // the 10-year span cap. The budget is SHARED across all rules in
  // the same expand call so an N-rule union can't amplify the
  // worst-case work past the single-rule bound.
  while (out.length < count && out.length < maxCount && ctx.stepBudgetRef.remaining > 0) {
    ctx.stepBudgetRef.remaining -= 1;
    if (t > untilMs) break;
    if (toMs !== null && t > toMs) break;
    if (_matchesBy(t)) {
      if (fromMs === null || t >= fromMs) {
        out.push(_msToIsoZ(t));
      }
    }
    t = _advance(t, freq, interval);
    if (t === null) {
      throw new CalendarError("calendar/bad-recurrence",
        "b.calendar.expandRecurrence: unsupported frequency '" + freq + "'");
    }
  }
  return { instances: out, stepBudgetRemaining: ctx.stepBudgetRef.remaining };
}

// Parse + validate rule.bySetPos. Returns null when absent / empty;
// otherwise an array of integers in [-366, -1] U [1, 366] (RFC 5545
// grammar). Zero values + out-of-range values are silently dropped.
function _bySetPosArray(raw) {
  if (!Array.isArray(raw) || raw.length === 0) return null;
  var out = [];
  for (var i = 0; i < raw.length; i += 1) {
    var n = parseInt(raw[i], 10);
    if (isFinite(n) && n !== 0 && n >= -366 && n <= 366) out.push(n);                                  // RFC 5545 §3.3.10 bysetpos range
  }
  return out.length > 0 ? out : null;
}

// BYSETPOS expander. Iterates by FREQ interval; for each period,
// enumerates day-level candidates within the period; applies the
// caller's matchesBy filter; sorts ascending; picks the position(s)
// per bySetPos. Time-of-day per candidate matches the rule's start.
function _expandWithBysetpos(ctx) {
  var startMs      = ctx.startMs;
  var freq         = ctx.freq;
  var interval     = ctx.interval;
  var count        = ctx.count;
  var untilMs      = ctx.untilMs;
  var fromMs       = ctx.fromMs;
  var toMs         = ctx.toMs;
  var maxCount     = ctx.maxCount;
  var matchesBy    = ctx.matchesBy;
  var bySetPos     = ctx.bySetPos;
  var stepBudgetRef = ctx.stepBudgetRef;

  if (freq !== "monthly" && freq !== "yearly" && freq !== "weekly") {
    throw new CalendarError("calendar/bad-recurrence",
      "b.calendar.expandRecurrence: BYSETPOS supported only with FREQ=MONTHLY / YEARLY / WEEKLY (got '" + freq + "')");
  }

  var startDate = new Date(startMs);
  var hh = startDate.getUTCHours();
  var mm = startDate.getUTCMinutes();
  var ss = startDate.getUTCSeconds();
  var ms = startDate.getUTCMilliseconds();

  var out = [];
  // Period anchor (period 0 = start's period).
  var periodIndex = 0;

  while (out.length < count && out.length < maxCount && stepBudgetRef.remaining > 0) {
    var period = _periodForIndex(freq, startDate, periodIndex * interval);
    periodIndex += 1;
    // Out-of-window early exit. Window-uppper applies once the period
    // start crosses toMs; until applies once period-start crosses untilMs.
    if (period.startMs > untilMs) break;
    if (toMs !== null && period.startMs > toMs) break;

    // Enumerate day-level candidates within the period at start's
    // time-of-day. The budget decrements per candidate so adversarial
    // periods (e.g. YEARLY = 366 days) can't loop forever.
    var candidates = [];
    var dayMs = period.startMs;
    var safety = 400;                                                                                  // period day cap (covers leap year 366 + slack)
    while (dayMs <= period.endMs && safety-- > 0 && stepBudgetRef.remaining > 0) {
      stepBudgetRef.remaining -= 1;
      var candidate = _withTimeOfDay(dayMs, hh, mm, ss, ms);
      if (matchesBy(candidate)) candidates.push(candidate);
      dayMs += 86400000;                                                                               // allow:raw-time-literal — 86400000 ms/day step
    }

    // Sort + apply BYSETPOS. Positive index 1-based from start;
    // negative from end. Out-of-range positions silently drop.
    candidates.sort(function (a, b) { return a - b; });
    var picked = Object.create(null);
    for (var pi = 0; pi < bySetPos.length; pi += 1) {
      var pos = bySetPos[pi];
      var idx = pos > 0 ? pos - 1 : candidates.length + pos;
      if (idx >= 0 && idx < candidates.length) picked[candidates[idx]] = true;
    }
    // Emit picked candidates in ascending order, gated by window +
    // untilMs + per-rule count cap.
    //
    // Recurrence instances MUST NOT precede DTSTART (per
    // RFC 5545 §3.8.5.3). The period-boundary enumeration above
    // includes candidates BEFORE startMs when the period containing
    // startMs has earlier BY*-matching days (e.g. start = May 20
    // Friday, BYDAY=FR;BYSETPOS=1 → enumeration would pick May 1).
    // Refusing pre-start candidates here both fixes the semantics
    // AND avoids consuming the per-rule COUNT cap on instances the
    // operator never asked for.
    var pickedKeys = Object.keys(picked).map(Number).sort(function (a, b) { return a - b; });
    for (var ki = 0; ki < pickedKeys.length; ki += 1) {
      var pickedMs = pickedKeys[ki];
      if (pickedMs < startMs) continue;
      if (pickedMs > untilMs) { count = out.length; break; }
      if (toMs !== null && pickedMs > toMs) { count = out.length; break; }
      if (fromMs !== null && pickedMs < fromMs) continue;
      if (out.length >= count || out.length >= maxCount) break;
      out.push(_msToIsoZ(pickedMs));
    }
  }
  return { instances: out, stepBudgetRemaining: stepBudgetRef.remaining };
}

// Compute period [startMs, endMs] given a base start date + interval
// offset. Period START is anchored at the first second of the period
// (Jan 1 for YEARLY, day 1 for MONTHLY, WKST-Monday for WEEKLY) so
// the day-enumeration loop strides whole-day from there.
function _periodForIndex(freq, startDate, offset) {
  if (freq === "yearly") {
    var year = startDate.getUTCFullYear() + offset;
    var ys = Date.UTC(year, 0, 1, 0, 0, 0, 0);
    var ye = Date.UTC(year + 1, 0, 1, 0, 0, 0, 0) - 1;
    return { startMs: ys, endMs: ye };
  }
  if (freq === "monthly") {
    var bm = startDate.getUTCMonth() + offset;
    var by = startDate.getUTCFullYear() + Math.floor(bm / 12);                                         // months/year
    var mm = ((bm % 12) + 12) % 12;                                                                    // months/year
    var ms = Date.UTC(by, mm, 1, 0, 0, 0, 0);
    var me = Date.UTC(by, mm + 1, 1, 0, 0, 0, 0) - 1;
    return { startMs: ms, endMs: me };
  }
  // weekly — align to WKST=Monday (RFC 5545 default WKST).
  var anchor = new Date(Date.UTC(startDate.getUTCFullYear(), startDate.getUTCMonth(), startDate.getUTCDate(), 0, 0, 0, 0));
  var dow = anchor.getUTCDay() || 7;
  anchor.setUTCDate(anchor.getUTCDate() - (dow - 1) + offset * 7);                                     // days/week
  var ws = anchor.getTime();
  var we = ws + 7 * 86400000 - 1;                                                                      // allow:raw-time-literal — 7-day window
  return { startMs: ws, endMs: we };
}

function _withTimeOfDay(dayMs, hh, mm, ss, ms) {
  var d = new Date(dayMs);
  return Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate(), hh, mm, ss, ms);
}

// ---- Internal helpers ----------------------------------------------------

function _veventToJsCalEvent(ve) {
  var props = (ve && ve.properties) || {};
  var jsCal = {
    "@type":  "Event",
    uid:      _firstValue(props.UID) || "",
    updated:  _icalDateTimeToUtc(_firstValue(props.DTSTAMP) || ""),
  };
  var summary = _firstValue(props.SUMMARY);
  if (summary) jsCal.title = _unescapeText(summary);
  var description = _firstValue(props.DESCRIPTION);
  if (description) jsCal.description = _unescapeText(description);
  var dtstart = _firstValue(props.DTSTART);
  if (dtstart) jsCal.start = _icalDateTimeToLocal(dtstart);
  var duration = _firstValue(props.DURATION);
  if (duration) jsCal.duration = duration;
  var tzid = _firstParamValue(props.DTSTART, "TZID");
  if (tzid) {
    jsCal.timeZone = tzid;
  } else if (typeof dtstart === "string" && /Z$/.test(dtstart)) {
    // RFC 8984 §1.4.4: a UTC-suffix DTSTART (`...Z`) in
    // iCalendar maps to a JSCalendar Event with `timeZone: "Etc/UTC"`.
    // Without this, round-tripping `fromIcal` → `toIcal` would drop
    // the UTC anchor + emit floating time, shifting the absolute
    // instant for viewers in different timezones.
    jsCal.timeZone = "Etc/UTC";
  }
  var location = _firstValue(props.LOCATION);
  if (location) {
    jsCal.locations = { L1: { "@type": "Location", name: _unescapeText(location) } };
  }
  var rrule = _firstValue(props.RRULE);
  if (rrule) jsCal.recurrenceRules = [_icalRruleToJscal(rrule)];
  return jsCal;
}

// RFC 8984 §6 — JSCalendar Task. The VTODO mapping is structurally
// similar to VEVENT but adds Task-specific properties:
//   DUE       → due (LocalDateTime)
//   STATUS    → progress ("needs-action"|"in-process"|"completed"|"cancelled")
//   PERCENT-COMPLETE → percentComplete (0..100)
//   COMPLETED → progressUpdated (UTCDateTime)
function _vtodoToJsCalTask(vt) {
  var props = (vt && vt.properties) || {};
  var jsCal = {
    "@type":  "Task",
    uid:      _firstValue(props.UID) || "",
    updated:  _icalDateTimeToUtc(_firstValue(props.DTSTAMP) || ""),
  };
  var summary = _firstValue(props.SUMMARY);
  if (summary) jsCal.title = _unescapeText(summary);
  var description = _firstValue(props.DESCRIPTION);
  if (description) jsCal.description = _unescapeText(description);
  var dtstart = _firstValue(props.DTSTART);
  if (dtstart) jsCal.start = _icalDateTimeToLocal(dtstart);
  var due = _firstValue(props.DUE);
  if (due) jsCal.due = _icalDateTimeToLocal(due);
  var duration = _firstValue(props.DURATION);
  if (duration) jsCal.estimatedDuration = duration;
  var tzid = _firstParamValue(props.DTSTART, "TZID") ||
             _firstParamValue(props.DUE, "TZID");
  if (tzid) {
    jsCal.timeZone = tzid;
  } else if ((typeof dtstart === "string" && /Z$/.test(dtstart)) ||
             (typeof due === "string" && /Z$/.test(due))) {
    jsCal.timeZone = "Etc/UTC";
  }
  var status = _firstValue(props.STATUS);
  if (status) {
    var statusLower = String(status).toLowerCase();
    var statusMap = {
      "needs-action": "needs-action",
      "in-process":   "in-process",
      "completed":    "completed",
      "cancelled":    "cancelled",
    };
    if (statusMap[statusLower]) jsCal.progress = statusMap[statusLower];
  }
  var percent = _firstValue(props["PERCENT-COMPLETE"]);
  if (percent !== null && percent !== undefined) {
    var pn = parseInt(percent, 10);
    if (isFinite(pn) && pn >= 0 && pn <= 100) jsCal.percentComplete = pn;                              // RFC 8984 §6 percent range
  }
  var completed = _firstValue(props.COMPLETED);
  if (completed) jsCal.progressUpdated = _icalDateTimeToUtc(completed);
  var location = _firstValue(props.LOCATION);
  if (location) {
    jsCal.locations = { L1: { "@type": "Location", name: _unescapeText(location) } };
  }
  var rrule2 = _firstValue(props.RRULE);
  if (rrule2) jsCal.recurrenceRules = [_icalRruleToJscal(rrule2)];
  return jsCal;
}

// RFC 5545 §3.6.3 — VJOURNAL maps to a JSCalendar-shaped Note. The
// VJOURNAL grammar permits MULTIPLE DESCRIPTION properties (the only
// iCalendar component that does); blamejs joins them with a single
// blank line to preserve operator-visible separators. STATUS is
// limited to DRAFT / FINAL / CANCELLED (different from VTODO's
// vocabulary), with no DUE / DURATION / PERCENT-COMPLETE / COMPLETED.
function _vjournalToJsCalNote(vj) {
  var props = (vj && vj.properties) || {};
  var jsCal = {
    "@type":  "Note",
    uid:      _firstValue(props.UID) || "",
    updated:  _icalDateTimeToUtc(_firstValue(props.DTSTAMP) || ""),
  };
  var summary = _firstValue(props.SUMMARY);
  if (summary) jsCal.title = _unescapeText(summary);
  // RFC 5545 §3.6.3 — VJOURNAL is the only component that may carry
  // multiple DESCRIPTION properties (one per discrete journal entry).
  // Concatenate them with a blank-line separator so downstream
  // consumers see the operator-visible boundaries.
  var descriptions = _allValues(props.DESCRIPTION);
  if (descriptions.length === 1) {
    jsCal.description = _unescapeText(descriptions[0]);
  } else if (descriptions.length > 1) {
    var parts = [];
    for (var di = 0; di < descriptions.length; di += 1) {
      parts.push(_unescapeText(descriptions[di]));
    }
    jsCal.description = parts.join("\n\n");
  }
  var dtstart = _firstValue(props.DTSTART);
  if (dtstart) jsCal.start = _icalDateTimeToLocal(dtstart);
  var tzid = _firstParamValue(props.DTSTART, "TZID");
  if (tzid) {
    jsCal.timeZone = tzid;
  } else if (typeof dtstart === "string" && /Z$/.test(dtstart)) {
    jsCal.timeZone = "Etc/UTC";
  }
  var status = _firstValue(props.STATUS);
  if (status) {
    var statusLower = String(status).toLowerCase();
    if (Object.prototype.hasOwnProperty.call(JSCAL_NOTE_STATUS, statusLower)) {
      jsCal.status = statusLower;
    }
  }
  var location = _firstValue(props.LOCATION);
  if (location) {
    jsCal.locations = { L1: { "@type": "Location", name: _unescapeText(location) } };
  }
  var rrule3 = _firstValue(props.RRULE);
  if (rrule3) jsCal.recurrenceRules = [_icalRruleToJscal(rrule3)];
  return jsCal;
}

function _allValues(prop) {
  if (!prop) return [];
  if (Array.isArray(prop)) {
    var out = [];
    for (var i = 0; i < prop.length; i += 1) {
      var item = prop[i];
      if (item && item.value !== undefined) out.push(item.value);
    }
    return out;
  }
  return prop.value !== undefined ? [prop.value] : [];
}

function _firstValue(prop) {
  if (!prop) return null;
  if (Array.isArray(prop)) {
    var first = prop[0];
    return first && first.value !== undefined ? first.value : null;
  }
  if (prop.value !== undefined) return prop.value;
  return null;
}

function _firstParamValue(prop, paramName) {
  if (!prop) return null;
  var first = Array.isArray(prop) ? prop[0] : prop;
  if (!first || !first.params) return null;
  return first.params[paramName] || null;
}

function _icalRruleToJscal(rrule) {
  var out = { "@type": "RecurrenceRule", frequency: "daily" };
  var parts = String(rrule).split(";");                                                                // allow:bare-split-on-quoted-header — RFC 5545 RRULE grammar has no quoted-string members; values are token-only
  for (var i = 0; i < parts.length; i += 1) {
    var kv = parts[i].split("=");
    if (kv.length !== 2) continue;
    var key = kv[0].toUpperCase();
    var val = kv[1];
    if (key === "FREQ") out.frequency = val.toLowerCase();
    else if (key === "INTERVAL") out.interval = parseInt(val, 10);
    else if (key === "COUNT") out.count = parseInt(val, 10);
    else if (key === "UNTIL") out.until = _icalDateTimeToUtc(val);
    else if (key === "BYDAY") out.byDay = val.split(",").map(function (d) {                            // allow:bare-split-on-quoted-header — RFC 5545 BYDAY values are token-only
      return { "@type": "NDay", day: d.slice(-2).toLowerCase() };
    });
    else if (key === "BYMONTH") out.byMonth = val.split(",");                                          // allow:bare-split-on-quoted-header — RFC 5545 BYMONTH values are integer-only
    else if (key === "BYMONTHDAY") out.byMonthDay = val.split(",").map(function (n) { return parseInt(n, 10); }); // allow:bare-split-on-quoted-header — RFC 5545 BYMONTHDAY values are integer-only
  }
  return out;
}

function _recurrenceRuleToIcal(rr) {
  var parts = ["FREQ=" + (rr.frequency || "daily").toUpperCase()];
  if (rr.interval && rr.interval !== 1) parts.push("INTERVAL=" + rr.interval);
  if (rr.count) parts.push("COUNT=" + rr.count);
  if (rr.until) parts.push("UNTIL=" + _utcDateTimeToIcal(rr.until));
  if (Array.isArray(rr.byDay) && rr.byDay.length > 0) {
    parts.push("BYDAY=" + rr.byDay.map(function (d) { return (d.day || "").toUpperCase(); }).join(","));
  }
  if (Array.isArray(rr.byMonth)) parts.push("BYMONTH=" + rr.byMonth.join(","));
  if (Array.isArray(rr.byMonthDay)) parts.push("BYMONTHDAY=" + rr.byMonthDay.join(","));
  return parts.join(";");
}

function _icalDateTimeToUtc(s) {
  // VALUE=DATE-TIME UTC form: 20260522T100000Z → 2026-05-22T10:00:00Z
  var m = String(s).match(/^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})Z$/);
  if (!m) return "";
  return m[1] + "-" + m[2] + "-" + m[3] + "T" + m[4] + ":" + m[5] + ":" + m[6] + "Z";
}

function _icalDateTimeToLocal(s) {
  var m = String(s).match(/^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})Z?$/);
  if (!m) return "";
  return m[1] + "-" + m[2] + "-" + m[3] + "T" + m[4] + ":" + m[5] + ":" + m[6];
}

function _utcDateTimeToIcal(s) {
  // JSCalendar UTCDateTime "2026-05-22T10:00:00.123Z" →
  // "20260522T100000Z" (RFC 5545 §3.3.5 form 2 has NO fractional
  // seconds; strict ICS consumers reject `T100000.123Z`).
  return String(s).replace(/\.\d+/, "").replace(/[-:]/g, "");                                          // allow:bare-split-on-quoted-header — not a header split
}

function _localDateTimeToIcal(s) {
  // JSCalendar LocalDateTime "2026-05-22T09:00:00.123" →
  // "20260522T090000" (same fractional-second strip as the UTC form).
  return String(s).replace(/\.\d+/, "").replace(/[-:]/g, "");                                          // allow:bare-split-on-quoted-header — not a header split
}

function _isUtcDateTime(s) {
  return /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/.test(s);
}

function _isLocalDateTime(s) {
  return /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?$/.test(s);
}

function _isDuration(s) {
  return /^-?P(\d+Y)?(\d+M)?(\d+D)?(T(\d+H)?(\d+M)?(\d+S)?)?$/.test(s);
}

function _localToUtc(localStr) {
  // Naive — treats LocalDateTime as already-UTC for the no-tz case.
  return localStr.endsWith("Z") ? localStr : localStr + "Z";
}

function _msToIsoZ(ms) {
  return time.toIso8601NoMs(new Date(ms));
}

function _advance(ms, freq, interval) {
  var d = new Date(ms);
  switch (freq) {
  case "daily":   d.setUTCDate(d.getUTCDate() + interval); break;
  case "weekly":  d.setUTCDate(d.getUTCDate() + 7 * interval); break;                                  // 7 days/week
  case "monthly": d.setUTCMonth(d.getUTCMonth() + interval); break;
  case "yearly":  d.setUTCFullYear(d.getUTCFullYear() + interval); break;
  case "hourly":  d.setUTCHours(d.getUTCHours() + interval); break;
  case "minutely": d.setUTCMinutes(d.getUTCMinutes() + interval); break;
  case "secondly": d.setUTCSeconds(d.getUTCSeconds() + interval); break;
  default: return null;
  }
  return d.getTime();
}

function _escapeText(s) {
  return String(s).replace(/\\/g, "\\\\").replace(/;/g, "\\;").replace(/,/g, "\\,").replace(/\n/g, "\\n");
}

function _unescapeText(s) {
  return String(s)
    .replace(/\\n/g, "\n").replace(/\\,/g, ",")
    .replace(/\\;/g, ";").replace(/\\\\/g, "\\");
}

function _foldLine(s) {
  // RFC 5545 §3.1 — content lines SHOULD NOT exceed 75 octets; fold
  // with CRLF + leading space. We let the joining code add the
  // trailing CRLF; this helper only inserts the intra-line fold.
  if (s.length <= 75) return s;                                                                        // RFC 5545 §3.1 line-length cap
  var out = "";
  for (var i = 0; i < s.length; i += 73) {                                                             // 73 = 75 minus the CR/LF wrap
    out += (i === 0 ? "" : "\r\n ") + s.slice(i, i + 73);                                              // same cap
  }
  return out;
}

module.exports = {
  validate:               validate,
  fromIcal:               fromIcal,
  toIcal:                 toIcal,
  expandRecurrence:       expandRecurrence,
  CalendarError:          CalendarError,
  JSCAL_TYPES:            JSCAL_TYPES,
  JSCAL_FREQUENCIES:      JSCAL_FREQUENCIES,
  JSCAL_ALERT_ACTIONS:    JSCAL_ALERT_ACTIONS,
  JSCAL_TASK_PROGRESS:    JSCAL_TASK_PROGRESS,
  JSCAL_NOTE_STATUS:      JSCAL_NOTE_STATUS,
  MAX_EXPAND_INSTANCES:   MAX_EXPAND_INSTANCES,
  MAX_EXPAND_SPAN_MS:     MAX_EXPAND_SPAN_MS,
};
