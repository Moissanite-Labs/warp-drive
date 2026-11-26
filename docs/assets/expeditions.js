// Expeditions re-render. The baked HTML copy stays if the fetch fails.
const list = document.querySelector("[data-expeditions]");
if (list) {
  fetch("../data/expeditions.json", { cache: "no-cache" })
    .then((r) => { if (!r.ok) throw new Error(r.status); return r.json(); })
    .then((data) => {
      const count = document.querySelector("[data-expeditions-count]");
      if (count) {
        const studies = data.records.filter((r) => r.kind === "study").length;
        const demos = data.records.filter((r) => r.kind === "demo").length;
        count.textContent = studies + " studies and " + demos + (demos === 1 ? " demo lane" : " demo lanes");
      }
      const frag = document.createDocumentFragment();
      for (const rec of data.records) {
        const art = document.createElement("article");
        art.className = "card";
        art.dataset.slug = rec.slug;
        const h = document.createElement("h3");
        h.textContent = rec.name;
        const meta = document.createElement("p");
        meta.className = "meta";
        meta.textContent = [rec.audit_id_readme || "No audit id",
          rec.audit_id_json && rec.audit_id_json !== rec.audit_id_readme ? "JSON: " + rec.audit_id_json : "",
          "Git last-touch " + rec.git_last_touch].filter(Boolean).join(" · ");
        const sum = document.createElement("p");
        sum.textContent = rec.summary;
        const scope = document.createElement("p");
        scope.className = "meta";
        scope.textContent = "Evidence scope: " + (rec.evidence_scope || "see study README")
          + " · Certificate: " + (rec.has_certificate ? "yes" : "none")
          + (rec.verdicts.length ? " · Verdicts: " + rec.verdicts.join(", ") : "")
          + " · Pinned commits: " + (rec.pinned_commit && rec.pinned_commit.length ? rec.pinned_commit.join(", ") : "not declared");
        const link = document.createElement("p");
        const a = document.createElement("a");
        a.href = "https://github.com/Moissanite-Labs/warp-drive/tree/main/" + rec.repo_path;
        a.textContent = "Open " + rec.repo_path + " in the repo";
        link.append(a);
        art.append(h, meta, sum, scope, link);
        frag.append(art);
      }
      list.replaceChildren(frag);
    })
    .catch(() => { /* baked copy remains the source of truth offline */ });
}
