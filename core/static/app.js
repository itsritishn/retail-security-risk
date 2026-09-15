/*
 * SentinelFloor dashboard client.
 *
 * Two rules are followed without exception in this file:
 *
 *  1. Untrusted text is only ever written through `textContent`, never `innerHTML`.
 *     Alert headlines and disposition notes are attacker-influenced: a note is free text
 *     typed by a member of staff and rendered back to a manager. `innerHTML` here would
 *     be a stored-XSS path straight to a manager's session, and the strict CSP is the
 *     backstop, not the primary defence.
 *
 *  2. Every state change goes through an authenticated HTTP request carrying the CSRF
 *     token. The WebSocket is receive-only. Accepting commands over the socket would
 *     bypass the CSRF check entirely.
 */

(function () {
  "use strict";

  var CSRF = document.querySelector('meta[name="csrf-token"]');
  var CSRF_TOKEN = CSRF ? CSRF.getAttribute("content") : "";

  var els = {
    list: document.getElementById("alert-list"),
    empty: document.getElementById("alert-empty"),
    template: document.getElementById("alert-template"),
    conn: document.getElementById("connection-state"),
    countOpen: document.getElementById("count-open"),
    countAck: document.getElementById("count-ack"),
    countResolved: document.getElementById("count-resolved"),
    cameras: document.getElementById("camera-list"),
    duressBanner: document.getElementById("duress-banner"),
    duressButtons: document.getElementById("duress-buttons"),
    duressActive: document.getElementById("duress-active"),
    duressList: document.getElementById("duress-list"),
    dialog: document.getElementById("resolve-dialog"),
    dialogForm: document.getElementById("resolve-form"),
    dialogContext: document.getElementById("resolve-context"),
    dialogError: document.getElementById("resolve-error"),
    disposition: document.getElementById("disposition"),
    note: document.getElementById("resolve-note"),
    noteRequired: document.getElementById("note-required"),
    cancel: document.getElementById("resolve-cancel"),
    staffing: document.getElementById("staffing-list"),
    statPrecision: document.getElementById("stat-precision"),
    statResponse: document.getElementById("stat-response"),
    statFp: document.getElementById("stat-fp"),
    statUnattended: document.getElementById("stat-unattended")
  };

  var state = { alerts: new Map(), resolvingId: null, socket: null, backoff: 1000 };

  // ---------------------------------------------------------------- helpers

  function api(path, options) {
    options = options || {};
    var headers = { Accept: "application/json" };
    if (options.body) {
      headers["Content-Type"] = "application/json";
    }
    if (options.method && options.method !== "GET") {
      headers["X-SF-CSRF"] = CSRF_TOKEN;
    }
    return fetch(path, {
      method: options.method || "GET",
      headers: headers,
      body: options.body ? JSON.stringify(options.body) : undefined,
      credentials: "same-origin"
    }).then(function (response) {
      if (response.status === 401) {
        window.location.href = "/login";
        throw new Error("unauthenticated");
      }
      if (!response.ok) {
        return response
          .json()
          .catch(function () {
            return { detail: "Request failed (" + response.status + ")" };
          })
          .then(function (body) {
            var detail = body && body.detail;
            throw new Error(typeof detail === "string" ? detail : "Request failed");
          });
      }
      return response.status === 204 ? null : response.json();
    });
  }

  function setConnection(label, cls) {
    if (!els.conn) return;
    els.conn.textContent = label;
    els.conn.className = "conn " + cls;
  }

  function relativeAge(seconds) {
    if (seconds == null) return "";
    if (seconds < 60) return Math.round(seconds) + "s ago";
    if (seconds < 3600) return Math.round(seconds / 60) + "m ago";
    return Math.round(seconds / 3600) + "h ago";
  }

  function percent(value) {
    return value == null ? "—" : Math.round(value * 100) + "%";
  }

  // ----------------------------------------------------------- alert render

  function reasonLines(rationale) {
    var lines = [];
    if (!rationale || !Array.isArray(rationale.contributions)) return lines;
    rationale.contributions.forEach(function (item) {
      if (!item || typeof item.label !== "string") return;
      var sign = item.delta > 0 ? "+" : "";
      var label = item.label.replace(/_/g, " ");
      var detail = item.detail ? " — " + item.detail : "";
      lines.push(label + ": " + sign + Number(item.delta).toFixed(3) + detail);
    });
    return lines;
  }

  function renderAlert(alert, isNew) {
    var existing = els.list.querySelector('[data-alert-id="' + alert.id + '"]');
    var node;

    if (existing) {
      node = existing;
    } else {
      node = els.template.content.firstElementChild.cloneNode(true);
      node.dataset.alertId = String(alert.id);
    }

    node.dataset.severity = alert.severity || "info";
    node.dataset.status = alert.status || "open";

    var chip = node.querySelector(".sev-chip");
    chip.textContent = (alert.severity || "info").toUpperCase();
    chip.className = "sev-chip sev-" + (alert.severity || "info");

    node.querySelector(".alert-headline").textContent = alert.headline || "Behavioural signal";

    var metaParts = [];
    if (alert.zone) metaParts.push(alert.zone);
    if (alert.camera) metaParts.push(alert.camera);
    if (alert.score != null) metaParts.push("score " + Number(alert.score).toFixed(2));
    if (alert.age_seconds != null) metaParts.push(relativeAge(alert.age_seconds));
    if (alert.status && alert.status !== "open") {
      metaParts.push(alert.status + (alert.acknowledged_by ? " by " + alert.acknowledged_by : ""));
    }
    node.querySelector(".alert-meta").textContent = metaParts.join(" · ");

    var reasons = node.querySelector(".reason-list");
    reasons.textContent = "";
    var lines = reasonLines(alert.rationale);
    if (!lines.length) {
      var li = document.createElement("li");
      li.textContent = "No breakdown recorded for this prompt.";
      reasons.appendChild(li);
    } else {
      lines.forEach(function (line) {
        var item = document.createElement("li");
        item.textContent = line;
        reasons.appendChild(item);
      });
    }

    var ackBtn = node.querySelector(".btn-ack");
    var resolveBtn = node.querySelector(".btn-resolve");

    ackBtn.disabled = alert.status !== "open";
    ackBtn.textContent = alert.status === "open" ? "Acknowledge" : "Acknowledged";
    resolveBtn.disabled = alert.status === "resolved";

    ackBtn.onclick = function () {
      ackBtn.disabled = true;
      api("/api/v1/alerts/" + alert.id + "/acknowledge", { method: "POST" })
        .then(function (updated) {
          state.alerts.set(updated.id, updated);
          renderAlert(updated, false);
          refreshCounters();
        })
        .catch(function (err) {
          ackBtn.disabled = false;
          window.alert(err.message);
        });
    };

    resolveBtn.onclick = function () {
      openResolveDialog(alert);
    };

    if (!existing) {
      if (els.empty) els.empty.hidden = true;
      if (isNew) {
        node.classList.add("is-new");
        els.list.insertBefore(node, els.list.firstChild);
      } else {
        els.list.appendChild(node);
      }
    }

    return node;
  }

  function refreshCounters() {
    return api("/api/v1/alerts/summary").then(function (summary) {
      if (els.countOpen) els.countOpen.textContent = summary.open;
      if (els.countAck) els.countAck.textContent = summary.acknowledged;
      if (els.countResolved) els.countResolved.textContent = summary.resolved;
    });
  }

  function loadAlerts() {
    return api("/api/v1/alerts?limit=50").then(function (alerts) {
      els.list.textContent = "";
      if (els.empty) {
        els.list.appendChild(els.empty);
        els.empty.hidden = alerts.length > 0;
      }
      state.alerts.clear();
      alerts.forEach(function (alert) {
        state.alerts.set(alert.id, alert);
        renderAlert(alert, false);
      });
    });
  }

  // ------------------------------------------------------- resolve dialog

  function updateNoteRequirement() {
    var required = els.disposition.value === "false_positive";
    els.noteRequired.hidden = !required;
    els.note.required = required;
  }

  function openResolveDialog(alert) {
    state.resolvingId = alert.id;
    els.dialogContext.textContent =
      (alert.headline || "Prompt") + (alert.zone ? " — " + alert.zone : "");
    els.note.value = "";
    els.disposition.value = "true_positive_recovered";
    els.dialogError.hidden = true;
    updateNoteRequirement();

    if (typeof els.dialog.showModal === "function") {
      els.dialog.showModal();
    } else {
      els.dialog.setAttribute("open", "open");
    }
    els.disposition.focus();
  }

  function closeResolveDialog() {
    state.resolvingId = null;
    if (typeof els.dialog.close === "function") {
      els.dialog.close();
    } else {
      els.dialog.removeAttribute("open");
    }
  }

  if (els.dialogForm) {
    els.disposition.addEventListener("change", updateNoteRequirement);
    els.cancel.addEventListener("click", closeResolveDialog);

    els.dialogForm.addEventListener("submit", function (event) {
      event.preventDefault();
      if (state.resolvingId == null) return;

      var body = { disposition: els.disposition.value, note: els.note.value.trim() };

      if (body.disposition === "false_positive" && !body.note) {
        els.dialogError.textContent =
          "Please add a short note so the cause can be reviewed.";
        els.dialogError.hidden = false;
        els.note.focus();
        return;
      }

      api("/api/v1/alerts/" + state.resolvingId + "/resolve", {
        method: "POST",
        body: body
      })
        .then(function (updated) {
          state.alerts.set(updated.id, updated);
          renderAlert(updated, false);
          closeResolveDialog();
          refreshCounters();
          loadInsights();
        })
        .catch(function (err) {
          els.dialogError.textContent = err.message;
          els.dialogError.hidden = false;
        });
    });
  }

  // -------------------------------------------------------------- cameras

  function loadCameras() {
    if (!els.cameras) return Promise.resolve();
    return api("/api/v1/admin/cameras")
      .then(function (cameras) {
        els.cameras.textContent = "";
        if (!cameras.length) {
          var none = document.createElement("li");
          none.className = "empty-state";
          none.textContent = "No cameras registered.";
          els.cameras.appendChild(none);
          return;
        }
        cameras.forEach(function (cam) {
          var li = document.createElement("li");
          var name = document.createElement("span");
          name.textContent = cam.name + (cam.zone ? " · " + cam.zone : "");
          var status = document.createElement("span");
          if (!cam.enabled) {
            status.className = "cam-state cam-off";
            status.textContent = "disabled";
          } else if (cam.stale) {
            status.className = "cam-state cam-stale";
            status.textContent = "not reporting";
          } else {
            status.className = "cam-state cam-ok";
            status.textContent = "live";
          }
          li.appendChild(name);
          li.appendChild(status);
          els.cameras.appendChild(li);
        });
      })
      .catch(function () {
        /* A duty-manager-only endpoint. Assistants get a 403 and simply see nothing. */
        els.cameras.textContent = "";
        var li = document.createElement("li");
        li.className = "empty-state";
        li.textContent = "Camera status is not available for your role.";
        els.cameras.appendChild(li);
      });
  }

  // -------------------------------------------------------------- insights

  function loadInsights() {
    if (!els.statPrecision) return Promise.resolve();

    var quality = api("/api/v1/analytics/detection-quality?window_days=14")
      .then(function (data) {
        els.statPrecision.textContent = percent(data.precision);
        els.statFp.textContent = String(data.false_positives);
        els.statUnattended.textContent = percent(data.unattended_rate);
        els.statResponse.textContent =
          data.median_time_to_acknowledge_seconds == null
            ? "—"
            : Math.round(data.median_time_to_acknowledge_seconds) + "s";
      })
      .catch(function () {});

    var staffing = api("/api/v1/analytics/staffing?days=28")
      .then(function (data) {
        if (!els.staffing) return;
        els.staffing.textContent = "";
        var rows = data.recommendations || [];
        if (!rows.length) {
          var none = document.createElement("li");
          none.className = "empty-state";
          none.textContent = "Not enough history yet.";
          els.staffing.appendChild(none);
          return;
        }
        rows.forEach(function (row) {
          var li = document.createElement("li");
          var strong = document.createElement("strong");
          strong.textContent = row.zone + " " + row.window_local;
          li.appendChild(strong);
          var span = document.createElement("span");
          span.textContent = " — " + row.alert_volume + " prompts in this slot";
          li.appendChild(span);
          els.staffing.appendChild(li);
        });
      })
      .catch(function () {});

    return Promise.all([quality, staffing]);
  }

  // ---------------------------------------------------------------- duress

  function showDuress(payload) {
    if (!els.duressBanner) return;
    els.duressBanner.textContent = "";

    var heading = document.createElement("h2");
    var labels = {
      threat: "Threat to a person",
      theft_in_progress: "Theft in progress",
      medical: "Medical emergency",
      test: "Alarm test"
    };
    heading.textContent =
      (labels[payload.kind] || "Duress activated") +
      (payload.zone ? " — " + payload.zone : "");
    els.duressBanner.appendChild(heading);

    if (payload.coded_announcement) {
      var coded = document.createElement("span");
      coded.className = "coded";
      coded.textContent = "Announce: " + payload.coded_announcement;
      els.duressBanner.appendChild(coded);
    }

    if (Array.isArray(payload.staff_guidance) && payload.staff_guidance.length) {
      var ul = document.createElement("ul");
      payload.staff_guidance.forEach(function (line) {
        var li = document.createElement("li");
        li.textContent = line;
        ul.appendChild(li);
      });
      els.duressBanner.appendChild(ul);
    }

    els.duressBanner.hidden = false;
    loadDuress();
  }

  function loadDuress() {
    if (!els.duressList) return Promise.resolve();
    return api("/api/v1/duress/active")
      .then(function (rows) {
        els.duressList.textContent = "";
        if (!rows.length) {
          els.duressActive.hidden = true;
          return;
        }
        els.duressActive.hidden = false;
        rows.forEach(function (row) {
          var li = document.createElement("li");
          var text = document.createElement("div");
          text.textContent =
            row.kind.replace(/_/g, " ") +
            (row.zone ? " · " + row.zone : "") +
            (row.acknowledged_at ? " · acknowledged" : " · awaiting acknowledgement");
          li.appendChild(text);

          if (!row.acknowledged_at) {
            var ack = document.createElement("button");
            ack.type = "button";
            ack.className = "btn btn-quiet";
            ack.textContent = "Acknowledge";
            ack.onclick = function () {
              ack.disabled = true;
              api("/api/v1/duress/" + row.id + "/acknowledge", { method: "POST" })
                .then(loadDuress)
                .catch(function (err) {
                  ack.disabled = false;
                  window.alert(err.message);
                });
            };
            li.appendChild(ack);
          }
          els.duressList.appendChild(li);
        });
      })
      .catch(function () {});
  }

  if (els.duressButtons) {
    els.duressButtons.addEventListener("click", function (event) {
      var button = event.target.closest("[data-duress-kind]");
      if (!button) return;

      var kind = button.getAttribute("data-duress-kind");
      var prompts = {
        threat: "Raise a threat alert to the whole team?",
        theft_in_progress: "Alert the team to a theft in progress?",
        medical: "Call for a first aider?",
        test: "Send a test alert?"
      };
      if (!window.confirm(prompts[kind] || "Raise this alert?")) return;

      button.disabled = true;
      api("/api/v1/duress/manual", {
        method: "POST",
        body: { kind: kind, request_public_broadcast: false }
      })
        .then(function (activation) {
          showDuress(activation);
        })
        .catch(function (err) {
          window.alert(err.message);
        })
        .then(function () {
          button.disabled = false;
        });
    });
  }

  // ------------------------------------------------------------- websocket

  function connect() {
    var scheme = window.location.protocol === "https:" ? "wss:" : "ws:";
    var socket = new WebSocket(scheme + "//" + window.location.host + "/ws/alerts");
    state.socket = socket;
    setConnection("Connecting…", "conn-pending");

    socket.onopen = function () {
      setConnection("Live", "conn-live");
      state.backoff = 1000;
    };

    socket.onmessage = function (event) {
      var message;
      try {
        message = JSON.parse(event.data);
      } catch (err) {
        return;
      }
      handleMessage(message);
    };

    socket.onclose = function () {
      setConnection("Reconnecting…", "conn-down");
      // Exponential backoff, capped. A tight reconnect loop from every terminal in the
      // store would turn a brief service restart into a self-inflicted flood.
      state.backoff = Math.min(state.backoff * 2, 30000);
      window.setTimeout(connect, state.backoff);
    };

    socket.onerror = function () {
      setConnection("Connection problem", "conn-down");
    };
  }

  function handleMessage(message) {
    if (!message || typeof message.kind !== "string") return;
    var data = message.data || {};

    switch (message.kind) {
      case "alert.new":
        state.alerts.set(data.id, data);
        renderAlert(
          {
            id: data.id,
            headline: data.headline,
            severity: data.severity,
            score: data.score,
            zone: data.zone,
            camera: data.camera,
            status: "open",
            age_seconds: 0,
            rationale: data.rationale
          },
          true
        );
        refreshCounters();
        break;

      case "alert.acknowledged":
      case "alert.resolved":
        loadAlerts().then(refreshCounters);
        break;

      case "duress.activated":
        showDuress(data);
        break;

      case "duress.acknowledged":
      case "duress.resolved":
        loadDuress();
        break;

      default:
        break;
    }
  }

  // ------------------------------------------------------------------ boot

  function boot() {
    loadAlerts()
      .then(refreshCounters)
      .then(loadCameras)
      .then(loadDuress)
      .then(loadInsights)
      .catch(function () {});

    connect();

    // Periodic reconciliation. The socket carries live changes, but a poll every 30
    // seconds keeps ages current and repairs the view after a missed message.
    window.setInterval(function () {
      loadAlerts().then(refreshCounters).catch(function () {});
    }, 30000);

    window.setInterval(function () {
      loadCameras().catch(function () {});
    }, 60000);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();
