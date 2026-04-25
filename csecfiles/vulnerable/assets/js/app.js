/* CSecFiles -- shared front-end helpers.
   Kept minimal on purpose: the security lessons live in the PHP backend. */

(function () {
    "use strict";

    document.addEventListener("DOMContentLoaded", function () {

        // Highlight the active sidebar link based on the current page name.
        var here = (location.pathname.split("/").pop() || "").toLowerCase();
        document.querySelectorAll(".sidebar__nav a").forEach(function (link) {
            var href = (link.getAttribute("href") || "").toLowerCase();
            if (!href) return;
            if (href === here || href.indexOf(here) === 0) {
                link.classList.add("is-active");
            }
        });

        // Generic "are you sure?" confirmation for destructive actions.
        document.querySelectorAll("[data-confirm]").forEach(function (el) {
            el.addEventListener("click", function (e) {
                var msg = el.getAttribute("data-confirm") || "Are you sure?";
                if (!window.confirm(msg)) {
                    e.preventDefault();
                }
            });
        });

        // Auto-dismiss success alerts after 4 seconds.
        document.querySelectorAll(".alert--success").forEach(function (a) {
            setTimeout(function () { a.style.display = "none"; }, 4000);
        });

        // Dashboard-only guard: prevent viewing/downloading other users' private docs via buttons.
        // Note: the underlying endpoints remain intentionally vulnerable (IDOR lesson).
        document.querySelectorAll(".js-private-doc-block").forEach(function (el) {
            el.addEventListener("click", function (e) {
                e.preventDefault();
                var action = (el.getAttribute("data-action") || "access").toLowerCase();
                var title = el.getAttribute("data-doc-title") || "this document";
                var owner = el.getAttribute("data-doc-owner") || "another user";
                var verb = (action === "download") ? "download" : "view";
                window.alert("Unauthorized: you cannot " + verb + " \"" + title + "\" (owned by " + owner + ") from the dashboard.");
            });
        });
    });
})();
